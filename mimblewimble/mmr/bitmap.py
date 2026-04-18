"""
mimblewimble/mmr/bitmap.py

BitmapChunk and BitmapAccumulator for PIBD output-leaf bitmap segments.

The spent-output bitmap is transmitted as a series of fixed-width chunks, each
covering BITMAP_SEGMENT_HEIGHT levels worth of leaves.  The BitmapAccumulator
reassembles received chunks into a single roaring bitmap used to determine
which output leaf positions are pruned (spent).

Grin reference:  chain/src/txhashset/bitmap_accumulator.rs
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import ClassVar, Iterator, List, Optional, Set

# ---------------------------------------------------------------------------
# BitmapChunk
# ---------------------------------------------------------------------------

# Each chunk covers this many bits (one per output leaf).
# Matches BITMAP_SEGMENT_HEIGHT = 9   →   2^9 = 512 bits per chunk.
CHUNK_BITS: int = 512  # 2^9
CHUNK_BYTES: int = CHUNK_BITS // 8  # 64 bytes


@dataclass
class BitmapChunk:
    """A fixed-width bit array covering ``CHUNK_BITS`` output leaf positions.

    Each bit indicates whether the corresponding output leaf is spent (1) or
    unspent (0).

    Wire format: raw ``CHUNK_BYTES`` bytes, little-endian bit order
    (bit 0 of byte 0 = leaf 0, bit 7 of byte 0 = leaf 7, etc.)
    """

    # Class-level aliases so callers can write BitmapChunk.CHUNK_BITS
    CHUNK_BITS: ClassVar[int] = CHUNK_BITS  # noqa: F821
    CHUNK_BYTES: ClassVar[int] = CHUNK_BYTES  # noqa: F821

    data: bytes = field(default_factory=lambda: b"\x00" * CHUNK_BYTES)

    def __post_init__(self) -> None:
        if len(self.data) != CHUNK_BYTES:
            raise ValueError(
                f"BitmapChunk expects {CHUNK_BYTES} bytes, got {len(self.data)}"
            )

    def is_set(self, bit: int) -> bool:
        """Return True if bit *bit* (0-based within this chunk) is set."""
        if bit < 0 or bit >= CHUNK_BITS:
            raise IndexError(f"Bit index {bit} out of range [0, {CHUNK_BITS})")
        byte_idx = bit // 8
        bit_idx = bit % 8
        return bool(self.data[byte_idx] & (1 << bit_idx))

    def set_bit(self, bit: int) -> "BitmapChunk":
        """Return a new BitmapChunk with bit *bit* set."""
        if bit < 0 or bit >= CHUNK_BITS:
            raise IndexError(f"Bit index {bit} out of range [0, {CHUNK_BITS})")
        data = bytearray(self.data)
        byte_idx = bit // 8
        bit_idx = bit % 8
        data[byte_idx] |= 1 << bit_idx
        return BitmapChunk(bytes(data))

    def iter_set_bits(self) -> Iterator[int]:
        """Yield 0-based positions of all set bits within this chunk."""
        for byte_idx, byte_val in enumerate(self.data):
            if byte_val == 0:
                continue
            for bit_idx in range(8):
                if byte_val & (1 << bit_idx):
                    yield byte_idx * 8 + bit_idx

    def serialize(self) -> bytes:
        """Return the raw byte representation."""
        return self.data

    @classmethod
    def deserialize(cls, data: bytes) -> "BitmapChunk":
        """Deserialize from raw bytes (exactly CHUNK_BYTES bytes)."""
        return cls(data=data[:CHUNK_BYTES])

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitmapChunk":
        """Alias for :meth:`deserialize` — construct from raw bytes."""
        return cls(data=data[:CHUNK_BYTES])

    def hash_leaf(self, pos0: int) -> bytes:
        """Compute the PMMR leaf hash for this chunk at MMR position *pos0*.

        Matches Grin's BitmapChunk::hash_to_leaf():
          blake2b_256(pos0_le64 | chunk_bytes)
        """
        import hashlib

        prefix = pos0.to_bytes(8, "little")
        return hashlib.blake2b(prefix + self.data, digest_size=32).digest()


# ---------------------------------------------------------------------------
# BitmapAccumulator
# ---------------------------------------------------------------------------


class BitmapAccumulator:
    """Assembles BitmapChunk segments into a complete spent-output bitmap.

    As bitmap segments arrive during PIBD sync they are applied to this
    accumulator.  Once all segments are received, ``finalize()`` returns
    a set (or pyroaring.BitMap) of spent leaf insertion indices.

    The accumulator also maintains a PMMR-of-bitmap-chunks for root
    verification: each chunk is a leaf in a PMMR keyed by chunk index.
    """

    def __init__(self) -> None:
        # chunk_idx → BitmapChunk
        self._chunks: dict[int, BitmapChunk] = {}
        self._total_chunks: Optional[int] = None
        self._finalized_bitmap: Optional[object] = None  # pyroaring.BitMap or set

    # ------------------------------------------------------------------
    # Chunk management
    # ------------------------------------------------------------------

    def apply_chunk(self, chunk_idx: int, chunk: BitmapChunk) -> None:
        """Store bitmap chunk at *chunk_idx*.

        Invalidates any previously finalized bitmap.
        """
        self._chunks[chunk_idx] = chunk
        self._finalized_bitmap = None

    def get_chunk_bytes(self, chunk_idx: int) -> bytes:
        """Return the serialised bytes for the chunk at *chunk_idx*.

        Returns an all-zeros chunk if that index has not been applied yet.
        """
        return self._chunks.get(chunk_idx, BitmapChunk()).serialize()

    def build_from_pmmr(self, output_pmmr: object) -> None:
        """Populate this accumulator from an output PMMR's prune bitmap.

        Iterates all pruned leaf insertion indices in *output_pmmr* and
        sets the corresponding bits in the appropriate chunks.  Used by
        :class:`Segmenter` to prepare the bitmap accumulator for sharing.

        *output_pmmr* must expose a ``_prune_bm`` attribute that supports
        ``pruned_insertion_indices()``.
        """
        self._chunks.clear()
        self._finalized_bitmap = None
        prune_bm = getattr(output_pmmr, "_prune_bm", None)
        if prune_bm is None:
            return
        for leaf_idx in prune_bm.pruned_insertion_indices():
            chunk_idx = leaf_idx // CHUNK_BITS
            bit_in_chunk = leaf_idx % CHUNK_BITS
            existing = self._chunks.get(chunk_idx, BitmapChunk())
            self._chunks[chunk_idx] = existing.set_bit(bit_in_chunk)

    def set_total_chunks(self, total: int) -> None:
        """Set the expected total number of chunks (used for completeness check)."""
        self._total_chunks = total

    def is_complete(self) -> bool:
        """Return True when all expected chunks have been received."""
        if self._total_chunks is None:
            return False
        return len(self._chunks) >= self._total_chunks

    # ------------------------------------------------------------------
    # Bitmap query
    # ------------------------------------------------------------------

    def finalize(self) -> object:
        """Return a set/bitset of spent output leaf insertion indices.

        Attempts to use ``pyroaring.BitMap`` for memory efficiency; falls
        back to a plain Python ``set`` if pyroaring is unavailable.

        Returns:
            An object supporting ``in`` checks and ``__iter__``.
        """
        if self._finalized_bitmap is not None:
            return self._finalized_bitmap

        try:
            from pyroaring import BitMap  # type: ignore

            bm: object = BitMap()
        except ImportError:
            bm = set()

        for chunk_idx in sorted(self._chunks.keys()):
            chunk = self._chunks[chunk_idx]
            base = chunk_idx * CHUNK_BITS
            for local_bit in chunk.iter_set_bits():
                if isinstance(bm, set):
                    bm.add(base + local_bit)
                else:
                    bm.add(base + local_bit)

        self._finalized_bitmap = bm
        return bm

    def is_spent(self, leaf_insertion_idx: int) -> bool:
        """Return True if the output at *leaf_insertion_idx* is spent."""
        bm = self.finalize()
        return leaf_insertion_idx in bm

    # ------------------------------------------------------------------
    # Bitmap root (for segment verification)
    # ------------------------------------------------------------------

    def root(self, n_outputs: int) -> Optional[bytes]:
        """Compute the PMMR root of bitmap chunks for a given output count.

        The bitmap PMMR has one leaf per chunk, where each leaf is
        BitmapChunk.hash_leaf(chunk_pos0).

        Returns None if the accumulator has no chunks.
        """
        from mimblewimble.mmr.proof import hash_with_index

        if not self._chunks:
            return None

        max_chunk = max(self._chunks.keys())
        leaf_hashes = []
        for i in range(max_chunk + 1):
            chunk = self._chunks.get(i, BitmapChunk())
            # leaf PMMR position is computed via insertion_to_pmmr_index
            from mimblewimble.mmr.index import insertion_to_pmmr_index

            pos0 = insertion_to_pmmr_index(i)
            leaf_hashes.append(chunk.hash_leaf(pos0))

        # Build a mini-PMMR of the leaf hashes and compute its root
        from mimblewimble.mmr.index import peaks, n_leaves
        import math

        n = len(leaf_hashes)
        if n == 0:
            return None

        # Compute the total MMR size for n leaves
        # (simple sequential push logic)
        hashes: list[Optional[bytes]] = []

        def push_leaf(data_hash: bytes) -> None:
            pos = len(hashes)
            h = hash_with_index(pos, data_hash)  # leaf-as-hash already, just wrap
            hashes.append(h)
            cur = pos
            while True:
                from mimblewimble.mmr.index import bintree_postorder_height, family

                height = bintree_postorder_height(cur)
                nxt = cur + 1
                if nxt < len(hashes) and bintree_postorder_height(nxt) == height + 1:
                    break
                if bintree_postorder_height(len(hashes)) != height + 1:
                    break
                right_h = hashes[cur]
                left_pos = cur - (1 << (height + 1)) + 1
                if left_pos < 0 or hashes[left_pos] is None:
                    break
                parent_pos = len(hashes)
                hashes.append(hash_with_index(parent_pos, hashes[left_pos] + right_h))
                cur = parent_pos

        for lh in leaf_hashes:
            push_leaf(lh)

        # Bag peaks
        mmr_size = len(hashes)
        all_peaks = peaks(mmr_size)
        if not all_peaks:
            return None

        acc: Optional[bytes] = None
        for p in reversed(all_peaks):
            ph = hashes[p]
            if ph is None:
                continue
            if acc is None:
                acc = ph
            else:
                acc = hash_with_index(mmr_size, ph + acc)

        return acc

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def serialize_chunks(self) -> bytes:
        """Serialize all stored chunks as:
        4-byte LE count | (8-byte LE chunk_idx | CHUNK_BYTES data)*
        """
        out = struct.pack("<I", len(self._chunks))
        for idx in sorted(self._chunks.keys()):
            out += struct.pack("<Q", idx)
            out += self._chunks[idx].serialize()
        return out

    @classmethod
    def deserialize_chunks(cls, data: bytes) -> "BitmapAccumulator":
        """Reconstruct from serialized chunks."""
        acc = cls()
        (n,) = struct.unpack_from("<I", data, 0)
        offset = 4
        for _ in range(n):
            (idx,) = struct.unpack_from("<Q", data, offset)
            offset += 8
            chunk = BitmapChunk(data[offset : offset + CHUNK_BYTES])
            offset += CHUNK_BYTES
            acc.apply_chunk(idx, chunk)
        if n > 0:
            acc.set_total_chunks(n)
        return acc

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._chunks.clear()
        self._total_chunks = None
        self._finalized_bitmap = None

    def __repr__(self) -> str:
        return (
            f"BitmapAccumulator(chunks={len(self._chunks)}, "
            f"complete={self.is_complete()})"
        )
