"""
tests/test_pibd_copy.py

Port of Grin's chain/tests/test_pibd_copy.rs:

  Builds a mini TxHashSet from a sequence of push() calls, then exercises
  the Segmenter/Desegmenter round-trip to verify that a fresh TxHashSet
  populated entirely from segments produces identical PMMR roots.

Only tests the in-memory / disk-backed path — no live node required.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from mimblewimble.mmr.pibd_params import (
    BITMAP_SEGMENT_HEIGHT,
    KERNEL_SEGMENT_HEIGHT,
    OUTPUT_SEGMENT_HEIGHT,
    RANGEPROOF_SEGMENT_HEIGHT,
)
from mimblewimble.mmr.segment import (
    SegmentIdentifier,
    SegmentType,
    SegmentTypeIdentifier,
)
from mimblewimble.mmr.txhashset import Desegmenter, Segmenter, TxHashSet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fake_commit(i: int) -> bytes:
    """Produce a deterministic 33-byte fake commitment."""
    return hashlib.blake2b(i.to_bytes(8, "little"), digest_size=33).digest()


def fake_rangeproof(i: int) -> bytes:
    """Produce a deterministic 32-byte fake rangeproof."""
    return hashlib.blake2b(b"rp" + i.to_bytes(8, "little"), digest_size=32).digest()


def fake_kernel(i: int) -> bytes:
    """Produce a deterministic 32-byte fake kernel."""
    return hashlib.blake2b(b"k" + i.to_bytes(8, "little"), digest_size=32).digest()


class FakeHeader:
    """Minimal header stub for Segmenter/Desegmenter."""

    def __init__(self, txhs: TxHashSet, height: int = 1) -> None:
        self.height = height
        self.outputMMRSize = txhs.output_pmmr.size()
        self.kernelMMRSize = txhs.kernel_mmr.size()
        self.outputRoot = txhs.output_pmmr.root()
        self.rangeProofRoot = txhs.rangeproof_pmmr.root()
        self.kernelRoot = txhs.kernel_mmr.root()
        self.totalKernelOffset = _FakeOffset()

    def getHash(self) -> bytes:
        return hashlib.blake2b(
            self.height.to_bytes(8, "little"), digest_size=32
        ).digest()


class _FakeOffset:
    def toSecretKey(self):
        return b"\x00" * 32


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def build_source_txhashset(n_outputs: int, n_kernels: int, tmp_dir: Path) -> TxHashSet:
    """Populate a TxHashSet with deterministic test data."""
    txhs = TxHashSet(tmp_dir / "source")
    for i in range(n_outputs):
        txhs.output_pmmr.push(fake_commit(i))
        txhs.rangeproof_pmmr.push(fake_rangeproof(i))
    for i in range(n_kernels):
        txhs.kernel_mmr.push(fake_kernel(i))
    txhs.flush()
    return txhs


@pytest.mark.parametrize(
    "n_outputs,n_kernels",
    [
        (1, 1),  # tiny
        (10, 5),  # small
        (512, 100),  # exactly one bitmap segment
        (513, 101),  # just over one bitmap segment
        (1024, 200),  # two bitmap segments
    ],
)
def test_pibd_round_trip(n_outputs, n_kernels, tmp_path):
    """Segmenter → Desegmenter round-trip produces identical roots."""
    src = build_source_txhashset(n_outputs, n_kernels, tmp_path)
    archive = FakeHeader(src, height=1)

    # ---- Segmenter: build bitmap accumulator from source prune bitmap ----
    from mimblewimble.mmr.bitmap import BitmapAccumulator

    bitmap = BitmapAccumulator()
    bitmap.build_from_pmmr(src.output_pmmr)
    segmenter = Segmenter(txhashset=src, bitmap_accumulator=bitmap, header=archive)

    # ---- Desegmenter: fresh empty TxHashSet ----
    dst = TxHashSet(tmp_path / "dest")
    deseg = dst.desegmenter(archive, genesis_header=None)

    from mimblewimble.mmr.index import n_leaves

    n_out = n_leaves(archive.outputMMRSize)
    n_chunks = (n_out + 511) // 512
    leaves_per_bitmap_seg = 1 << BITMAP_SEGMENT_HEIGHT
    n_bitmap_segs = (n_chunks + leaves_per_bitmap_seg - 1) // leaves_per_bitmap_seg

    leaves_per_out_seg = 1 << OUTPUT_SEGMENT_HEIGHT
    n_out_segs = (n_out + leaves_per_out_seg - 1) // leaves_per_out_seg

    n_kern_leaves = n_leaves(archive.kernelMMRSize)
    leaves_per_kern_seg = 1 << KERNEL_SEGMENT_HEIGHT
    n_kern_segs = (n_kern_leaves + leaves_per_kern_seg - 1) // leaves_per_kern_seg

    # Deliver bitmap segments
    for i in range(n_bitmap_segs):
        ident = SegmentIdentifier(height=BITMAP_SEGMENT_HEIGHT, idx=i)
        try:
            seg = segmenter.bitmap_segment(ident)
            # Use a permissive proof: skip verify for now (proof= empty)
            deseg._bitmap_segs_received.add(i)
            deseg._pending_bitmap[i] = seg
        except Exception:
            break

    # Deliver output segments
    for i in range(n_out_segs):
        ident = SegmentIdentifier(height=OUTPUT_SEGMENT_HEIGHT, idx=i)
        try:
            seg = segmenter.output_segment(ident)
            deseg._output_segs_received.add(i)
            deseg._pending_output[i] = seg
        except Exception:
            break

    # Deliver rangeproof segments (same count as output)
    for i in range(n_out_segs):
        ident = SegmentIdentifier(height=RANGEPROOF_SEGMENT_HEIGHT, idx=i)
        try:
            seg = segmenter.rangeproof_segment(ident)
            deseg._rangeproof_segs_received.add(i)
            deseg._pending_rangeproof[i] = seg
        except Exception:
            break

    # Deliver kernel segments
    for i in range(n_kern_segs):
        ident = SegmentIdentifier(height=KERNEL_SEGMENT_HEIGHT, idx=i)
        try:
            seg = segmenter.kernel_segment(ident)
            deseg._kernel_segs_received.add(i)
            deseg._pending_kernel[i] = seg
        except Exception:
            break

    # Apply all pending segments
    max_iterations = (n_bitmap_segs + n_out_segs + n_out_segs + n_kern_segs) * 2 + 10
    for _ in range(max_iterations):
        applied = deseg.apply_next_segments()
        if applied == 0:
            break

    dst.flush()

    # ---- Compare roots ----
    src_output_root = src.output_pmmr.root()
    dst_output_root = dst.output_pmmr.root()

    src_rp_root = src.rangeproof_pmmr.root()
    dst_rp_root = dst.rangeproof_pmmr.root()

    src_kern_root = src.kernel_mmr.root()
    dst_kern_root = dst.kernel_mmr.root()

    assert dst_output_root == src_output_root, (
        f"Output root mismatch for n_outputs={n_outputs}: "
        f"src={src_output_root.hex()} dst={dst_output_root.hex()}"
    )
    assert (
        dst_rp_root == src_rp_root
    ), f"Rangeproof root mismatch for n_outputs={n_outputs}"
    assert (
        dst_kern_root == src_kern_root
    ), f"Kernel root mismatch for n_kernels={n_kernels}"

    src.close()
    dst.close()


def test_desegmenter_is_complete_after_all_segments(tmp_path):
    """Desegmenter.is_complete() returns True once all required segments arrive."""
    n_outputs = 5
    n_kernels = 3
    src = build_source_txhashset(n_outputs, n_kernels, tmp_path)
    archive = FakeHeader(src, height=1)

    from mimblewimble.mmr.bitmap import BitmapAccumulator
    from mimblewimble.mmr.index import n_leaves

    bitmap = BitmapAccumulator()
    bitmap.build_from_pmmr(src.output_pmmr)
    segmenter = Segmenter(txhashset=src, bitmap_accumulator=bitmap, header=archive)

    dst = TxHashSet(tmp_path / "dest2")
    deseg = dst.desegmenter(archive, genesis_header=None)

    assert not deseg.is_complete()

    # Inject all required segment indices directly (skipping actual proof verification)
    deseg._bitmap_segs_received = set(range(deseg._n_bitmap_segs))
    deseg._output_segs_received = set(range(deseg._n_output_segs))
    deseg._rangeproof_segs_received = set(range(deseg._n_rangeproof_segs))
    deseg._kernel_segs_received = set(range(deseg._n_kernel_segs))

    assert deseg.is_complete()

    src.close()
    dst.close()


def test_next_desired_segments_ordering(tmp_path):
    """next_desired_segments() returns bitmap segments before output segments."""
    n_outputs = 600  # spans 2 bitmap segments
    src = build_source_txhashset(n_outputs, 1, tmp_path)
    archive = FakeHeader(src, height=1)

    dst = TxHashSet(tmp_path / "dest3")
    deseg = dst.desegmenter(archive, genesis_header=None)

    desired = deseg.next_desired_segments(10)
    assert len(desired) > 0
    # First desired must be bitmap
    assert desired[0].segment_type == SegmentType.BITMAP

    src.close()
    dst.close()
