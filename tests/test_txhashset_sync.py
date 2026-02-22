import tempfile
import zipfile
from pathlib import Path

import pytest

from mimblewimble.mmr.sync import TxHashSetSync
from mimblewimble.mmr.txhashset import TxHashSetError


def _make_zip(path: Path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)


def test_extract_skips_zip_slip_paths():
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        zip_path = base / "txhs.zip"
        out_dir = base / "out"

        _make_zip(
            zip_path,
            [
                ("../evil.txt", b"evil"),
                ("output/pmmr_hash.bin", b"ok"),
            ],
        )

        TxHashSetSync.extract(zip_path, out_dir)

        assert (out_dir / "output" / "pmmr_hash.bin").exists()
        assert not (base / "evil.txt").exists()


def test_extract_rejects_high_compression_ratio():
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        zip_path = base / "bomb.zip"
        out_dir = base / "out"

        # Highly compressible payload to trigger compression-ratio guard
        _make_zip(zip_path, [("output/pmmr_hash.bin", b"\x00" * (2 * 1024 * 1024))])

        original_ratio = TxHashSetSync._MAX_COMPRESSION_RATIO
        try:
            TxHashSetSync._MAX_COMPRESSION_RATIO = 5
            with pytest.raises(TxHashSetError):
                TxHashSetSync.extract(zip_path, out_dir)
        finally:
            TxHashSetSync._MAX_COMPRESSION_RATIO = original_ratio


def test_extract_rejects_total_uncompressed_limit():
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        zip_path = base / "large.zip"
        out_dir = base / "out"

        _make_zip(
            zip_path,
            [
                ("output/pmmr_hash.bin", b"a" * 256),
                ("rangeproof/pmmr_hash.bin", b"b" * 256),
            ],
        )

        original_limit = TxHashSetSync._MAX_ZIP_UNCOMPRESSED_BYTES
        try:
            TxHashSetSync._MAX_ZIP_UNCOMPRESSED_BYTES = 300
            with pytest.raises(TxHashSetError):
                TxHashSetSync.extract(zip_path, out_dir)
        finally:
            TxHashSetSync._MAX_ZIP_UNCOMPRESSED_BYTES = original_limit
