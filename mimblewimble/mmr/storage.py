"""
mimblewimble/mmr/storage.py

Disk-backed storage primitives for PMMR nodes, leaf data, and prune bitmaps.
The on-disk layout mirrors the Grin reference node so that TxHashSet ZIP
archives from a live Grin node can be loaded without conversion.

Files per PMMR:
    {name}_hash.bin   – flat array of 32-byte hashes, one per MMR position (0-based)
    {name}_data.bin   – flat concatenation of variable-length leaf data
    {name}_data_idx.bin – flat array of (offset: u64, length: u64) pairs, one per leaf

Prune bitmap (outputs & rangeproofs only):
    {name}_prune.bin  – serialised Roaring bitmap of pruned leaf insertion indices
"""

from __future__ import annotations

import mmap
import os
import struct
from pathlib import Path
from typing import Optional

# Try pyroaring for Grin-compatible bitmap serialisation; fall back to a pure
# Python dict-backed bitmap so the module can be imported without it for basic
# in-memory use.
try:
    from pyroaring import BitMap as _RoaringBitMap  # type: ignore

    _HAS_ROARING = True
except ImportError:  # pragma: no cover
    _HAS_ROARING = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HASH_SIZE = 32  # bytes per stored hash
IDX_ENTRY_SIZE = 16  # 8-byte offset + 8-byte length


# ---------------------------------------------------------------------------
# MMRHashFile
# ---------------------------------------------------------------------------


class MMRHashFile:
    """Flat binary file storing one 32-byte hash per MMR position (0-based).

    Reads are served via mmap for O(1) random access without loading the
    entire file.  Writes are buffered and flushed explicitly.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Open/create for read+write
        if not self._path.exists():
            self._path.write_bytes(b"")
        self._fh = open(self._path, "r+b")
        self._write_buf: list[bytes] = []  # buffered hashes not yet flushed
        self._disk_size = self._path.stat().st_size // HASH_SIZE  # positions on disk
        self._mmap: Optional[mmap.mmap] = None
        self._refresh_mmap()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh_mmap(self) -> None:
        """Recreate the mmap after a flush so reads reflect new data."""
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._disk_size > 0:
            self._mmap = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def size(self) -> int:
        """Total number of hash positions (disk + write buffer)."""
        return self._disk_size + len(self._write_buf)

    def get(self, pos0: int) -> Optional[bytes]:
        """Return the 32-byte hash at 0-based position *pos0*, or None if missing."""
        disk_size = self._disk_size
        buf_start = disk_size
        total = disk_size + len(self._write_buf)
        if pos0 < 0 or pos0 >= total:
            return None
        if pos0 >= buf_start:
            return self._write_buf[pos0 - buf_start]
        # Read from mmap
        if self._mmap is None:
            return None
        offset = pos0 * HASH_SIZE
        return bytes(self._mmap[offset : offset + HASH_SIZE])

    def append(self, h: bytes) -> None:
        """Buffer a 32-byte hash for the next position."""
        assert len(h) == HASH_SIZE, f"Hash must be {HASH_SIZE} bytes, got {len(h)}"
        self._write_buf.append(h)

    def set(self, pos0: int, h: bytes) -> None:
        """Overwrite an existing on-disk hash (used by pruning compaction)."""
        assert len(h) == HASH_SIZE
        disk_size = self._disk_size
        if pos0 < disk_size:
            self._fh.seek(pos0 * HASH_SIZE)
            self._fh.write(h)
            self._fh.flush()
            self._refresh_mmap()
        else:
            idx = pos0 - disk_size
            if idx < len(self._write_buf):
                self._write_buf[idx] = h

    def flush(self) -> None:
        """Write the buffer to disk."""
        if not self._write_buf:
            return
        self._fh.seek(0, 2)  # seek to end
        for h in self._write_buf:
            self._fh.write(h)
        self._fh.flush()
        self._disk_size += len(self._write_buf)
        self._write_buf.clear()
        self._refresh_mmap()

    def rewind(self, new_size: int) -> None:
        """Truncate to *new_size* positions, discarding anything beyond."""
        self.flush()
        if new_size >= self._disk_size:
            return
        self._fh.seek(0)
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        self._fh.close()
        # Truncate file
        with open(self._path, "r+b") as f:
            f.truncate(new_size * HASH_SIZE)
        self._fh = open(self._path, "r+b")
        self._disk_size = new_size
        self._write_buf.clear()
        self._refresh_mmap()

    def close(self) -> None:
        self.flush()
        if self._mmap is not None:
            self._mmap.close()
        self._fh.close()

    def __len__(self) -> int:
        return self.size()


# ---------------------------------------------------------------------------
# MMRDataFile
# ---------------------------------------------------------------------------


class MMRDataFile:
    """Variable-length leaf data store.

    Layout:
        {name}_data.bin     – raw leaf bytes, concatenated
        {name}_data_idx.bin – (uint64 offset, uint64 length) per leaf, LE

    The index file allows O(1) random access to any leaf by insertion index.
    """

    def __init__(self, data_path: Path, index_path: Path) -> None:
        self._data_path = Path(data_path)
        self._idx_path = Path(index_path)
        self._data_path.parent.mkdir(parents=True, exist_ok=True)

        for p in (self._data_path, self._idx_path):
            if not p.exists():
                p.write_bytes(b"")

        self._data_fh = open(self._data_path, "r+b")
        self._idx_fh = open(self._idx_path, "r+b")

        self._disk_leaf_count = self._idx_path.stat().st_size // IDX_ENTRY_SIZE
        self._disk_data_size = self._data_path.stat().st_size

        # In-memory buffers: list of raw bytes per leaf
        self._data_buf: list[bytes] = []

    # ------------------------------------------------------------------
    def data_size(self) -> int:
        """Number of stored leaves (disk + buffer)."""
        return self._disk_leaf_count + len(self._data_buf)

    def get_data(self, leaf_idx: int) -> Optional[bytes]:
        """Return raw bytes for 0-based *leaf_idx*, or None if out of range."""
        total = self.data_size()
        if leaf_idx < 0 or leaf_idx >= total:
            return None
        disk_count = self._disk_leaf_count
        if leaf_idx >= disk_count:
            return self._data_buf[leaf_idx - disk_count]
        # Read index entry
        self._idx_fh.seek(leaf_idx * IDX_ENTRY_SIZE)
        entry = self._idx_fh.read(IDX_ENTRY_SIZE)
        offset, length = struct.unpack("<QQ", entry)
        self._data_fh.seek(offset)
        return self._data_fh.read(length)

    def append_data(self, data: bytes) -> int:
        """Buffer leaf *data* and return its 0-based leaf index."""
        idx = self.data_size()
        self._data_buf.append(data)
        return idx

    def flush(self) -> None:
        """Write buffers to disk."""
        if not self._data_buf:
            return
        # Figure out current end-of-data offset
        current_offset = self._disk_data_size
        self._data_fh.seek(0, 2)
        self._idx_fh.seek(0, 2)
        for data in self._data_buf:
            self._data_fh.write(data)
            self._idx_fh.write(struct.pack("<QQ", current_offset, len(data)))
            current_offset += len(data)
        self._data_fh.flush()
        self._idx_fh.flush()
        self._disk_leaf_count += len(self._data_buf)
        self._disk_data_size = current_offset
        self._data_buf.clear()

    def rewind(self, new_leaf_count: int) -> None:
        """Truncate to *new_leaf_count* leaves."""
        self.flush()
        if new_leaf_count >= self._disk_leaf_count:
            return
        if new_leaf_count == 0:
            new_data_size = 0
        else:
            self._idx_fh.seek((new_leaf_count - 1) * IDX_ENTRY_SIZE)
            entry = self._idx_fh.read(IDX_ENTRY_SIZE)
            off, ln = struct.unpack("<QQ", entry)
            new_data_size = off + ln

        for fh, path, size in [
            (self._data_fh, self._data_path, new_data_size),
            (self._idx_fh, self._idx_path, new_leaf_count * IDX_ENTRY_SIZE),
        ]:
            fh.close()
            with open(path, "r+b") as f:
                f.truncate(size)

        self._data_fh = open(self._data_path, "r+b")
        self._idx_fh = open(self._idx_path, "r+b")
        self._disk_leaf_count = new_leaf_count
        self._disk_data_size = new_data_size

    def close(self) -> None:
        self.flush()
        self._data_fh.close()
        self._idx_fh.close()


# ---------------------------------------------------------------------------
# PruneBitmap
# ---------------------------------------------------------------------------


class PruneBitmap:
    """Bitmap of pruned leaf insertion indices (0-based).

    Uses pyroaring.BitMap when available (Grin ZIP-compatible serialisation),
    otherwise falls back to a plain Python set (sufficient for tests and
    non-sync use-cases).
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if _HAS_ROARING:
            self._bm = _RoaringBitMap()
        else:
            self._bm_set: set[int] = set()
        if self._path.exists() and self._path.stat().st_size > 0:
            self.load()

    # ------------------------------------------------------------------
    def mark_pruned(self, leaf_idx: int) -> None:
        if _HAS_ROARING:
            self._bm.add(leaf_idx)
        else:
            self._bm_set.add(leaf_idx)

    def is_pruned(self, leaf_idx: int) -> bool:
        if _HAS_ROARING:
            return leaf_idx in self._bm
        return leaf_idx in self._bm_set

    def pruned_insertion_indices(self):
        """Iterator over all pruned leaf insertion indices."""
        if _HAS_ROARING:
            return iter(self._bm)
        return iter(sorted(self._bm_set))

    def count(self) -> int:
        if _HAS_ROARING:
            return len(self._bm)
        return len(self._bm_set)

    def save(self) -> None:
        if _HAS_ROARING:
            data = self._bm.serialize()
        else:
            # Simple binary format: sorted uint32 list
            indices = sorted(self._bm_set)
            data = struct.pack(f"<{len(indices)}I", *indices) if indices else b""
        self._path.write_bytes(data)

    def load(self) -> None:
        data = self._path.read_bytes()
        if not data:
            return
        if _HAS_ROARING:
            self._bm = _RoaringBitMap.deserialize(data)
        else:
            count = len(data) // 4
            self._bm_set = set(struct.unpack(f"<{count}I", data))

    def rewind(self, max_leaf_idx: int) -> None:
        """Remove all entries with index >= *max_leaf_idx*."""
        if _HAS_ROARING:
            to_remove = [i for i in self._bm if i >= max_leaf_idx]
            for i in to_remove:
                self._bm.discard(i)
        else:
            self._bm_set = {i for i in self._bm_set if i < max_leaf_idx}
