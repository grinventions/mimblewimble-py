"""
tests/test_pibd_snapshot.py

Tests for the TxHashSet snapshot (ZIP fallback) path.

Verifies that ``StateSync.apply_snapshot()`` accepts a ZIP whose embedded
PMMR roots match the Stage-1 header and rejects one with tampered roots.
"""

import hashlib
import io
import tempfile
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

from mimblewimble.mmr.sync import TxHashSetSync
from mimblewimble.mmr.txhashset import TxHashSet
from mimblewimble.p2p.state_sync import StateSync, StateSyncError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_and_zip_txhashset(tmp_dir: Path, n_outputs: int, n_kernels: int):
    """Build a TxHashSet, snapshot it to ZIP, and return (zip_bytes, header_info)."""
    txhs = TxHashSet(tmp_dir / "src")

    for i in range(n_outputs):
        data = hashlib.blake2b(i.to_bytes(8, "little"), digest_size=33).digest()
        txhs.output_pmmr.push(data)
        rp = hashlib.blake2b(b"rp" + i.to_bytes(8, "little"), digest_size=32).digest()
        txhs.rangeproof_pmmr.push(rp)

    for i in range(n_kernels):
        kern = hashlib.blake2b(b"k" + i.to_bytes(8, "little"), digest_size=32).digest()
        txhs.kernel_mmr.push(kern)

    txhs.flush()

    output_root = txhs.output_pmmr.root()
    rp_root = txhs.rangeproof_pmmr.root()
    kern_root = txhs.kernel_mmr.root()
    output_mmr_size = txhs.output_pmmr.size()
    kernel_mmr_size = txhs.kernel_mmr.size()

    # Create a ZIP of the txhashset
    zip_path = txhs.snapshot(_FakeHeader(output_mmr_size, kernel_mmr_size))
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    txhs.close()
    return zip_bytes, output_root, rp_root, kern_root


class _FakeHeader:
    def __init__(self, output_mmr_size, kernel_mmr_size):
        self.height = 1
        self.outputMMRSize = output_mmr_size
        self.kernelMMRSize = kernel_mmr_size

    def getHash(self):
        return b"\xab" * 32


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_snapshot_accepted_with_correct_roots(tmp_path):
    """apply_snapshot() returns True when all roots match."""
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    zip_bytes, out_root, rp_root, kern_root = build_and_zip_txhashset(
        src_dir, n_outputs=5, n_kernels=3
    )

    txhs = TxHashSet(tmp_path / "live")
    state_sync = _make_state_sync(tmp_path, txhs)

    result = state_sync.apply_snapshot(
        block_hash=b"\xab" * 32,
        height=1,
        zip_bytes=zip_bytes,
        expected_output_root=out_root,
        expected_rangeproof_root=rp_root,
        expected_kernel_root=kern_root,
    )
    assert result is True
    txhs.close()


def test_snapshot_rejected_with_wrong_output_root(tmp_path):
    """apply_snapshot() raises StateSyncError when output root doesn't match."""
    src_dir = tmp_path / "src_dir2"
    src_dir.mkdir()
    zip_bytes, out_root, rp_root, kern_root = build_and_zip_txhashset(
        src_dir, n_outputs=5, n_kernels=3
    )

    txhs = TxHashSet(tmp_path / "live2")
    state_sync = _make_state_sync(tmp_path, txhs)

    wrong_root = b"\xff" * 32
    with pytest.raises(StateSyncError, match="output root mismatch"):
        state_sync.apply_snapshot(
            block_hash=b"\xab" * 32,
            height=1,
            zip_bytes=zip_bytes,
            expected_output_root=wrong_root,
            expected_rangeproof_root=rp_root,
            expected_kernel_root=kern_root,
        )
    txhs.close()


def test_snapshot_rejected_with_wrong_kernel_root(tmp_path):
    """apply_snapshot() raises StateSyncError on kernel root mismatch."""
    src_dir = tmp_path / "src_dir3"
    src_dir.mkdir()
    zip_bytes, out_root, rp_root, kern_root = build_and_zip_txhashset(
        src_dir, n_outputs=3, n_kernels=2
    )

    txhs = TxHashSet(tmp_path / "live3")
    state_sync = _make_state_sync(tmp_path, txhs)

    with pytest.raises(StateSyncError, match="kernel root mismatch"):
        state_sync.apply_snapshot(
            block_hash=b"\xab" * 32,
            height=1,
            zip_bytes=zip_bytes,
            expected_output_root=out_root,
            expected_rangeproof_root=rp_root,
            expected_kernel_root=b"\x00" * 32,
        )
    txhs.close()


def test_snapshot_rejected_with_bad_zip(tmp_path):
    """apply_snapshot() raises StateSyncError when the ZIP is corrupt."""
    txhs = TxHashSet(tmp_path / "live4")
    state_sync = _make_state_sync(tmp_path, txhs)

    with pytest.raises(StateSyncError):
        state_sync.apply_snapshot(
            block_hash=b"\xab" * 32,
            height=1,
            zip_bytes=b"not a zip file at all",
            expected_output_root=b"\x00" * 32,
            expected_rangeproof_root=b"\x00" * 32,
            expected_kernel_root=b"\x00" * 32,
        )
    txhs.close()


def test_snapshot_rejected_on_zip_slip_payload(tmp_path):
    """apply_snapshot() should not write zip-slip entries outside extraction dir."""
    txhs = TxHashSet(tmp_path / "live5")
    state_sync = _make_state_sync(tmp_path, txhs)

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../evil.txt", b"evil")
        zf.writestr("output/pmmr_hash.bin", b"ok")

    state_sync.apply_snapshot(
        block_hash=b"\xab" * 32,
        height=1,
        zip_bytes=payload.getvalue(),
        expected_output_root=b"\x00" * 32,
        expected_rangeproof_root=b"\x00" * 32,
        expected_kernel_root=b"\x00" * 32,
    )

    assert not (tmp_path / "evil.txt").exists()
    txhs.close()


def test_snapshot_rejected_on_suspicious_zip_ratio(tmp_path, monkeypatch):
    """apply_snapshot() should fail when extract safety ratio checks trigger."""
    txhs = TxHashSet(tmp_path / "live6")
    state_sync = _make_state_sync(tmp_path, txhs)

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("output/pmmr_hash.bin", b"\x00" * (2 * 1024 * 1024))

    monkeypatch.setattr(TxHashSetSync, "_MAX_COMPRESSION_RATIO", 5)
    with pytest.raises(StateSyncError, match="Failed to extract snapshot ZIP"):
        state_sync.apply_snapshot(
            block_hash=b"\xab" * 32,
            height=1,
            zip_bytes=payload.getvalue(),
            expected_output_root=b"\x00" * 32,
            expected_rangeproof_root=b"\x00" * 32,
            expected_kernel_root=b"\x00" * 32,
        )
    txhs.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state_sync(tmp_path: Path, txhs: TxHashSet) -> StateSync:
    from mimblewimble.mmr.pibd import SyncState
    from mimblewimble.p2p.adapter import NoopChainAdapter

    class _NullPeers:
        def count(self):
            return 0

        def pibd_capable(self):
            return _NQ()

        def txhashset_capable(self):
            return _NQ()

    class _NQ:
        def highest_difficulty(self):
            return self

        def pick(self):
            return None

        def pick_n(self, n):
            return []

    return StateSync(
        adapter=NoopChainAdapter(),
        peers=cast(Any, _NullPeers()),
        sync_state=SyncState(),
        txhashset=txhs,
        data_dir=tmp_path / "data",
    )
