"""
mimblewimble/mmr/segment.py

PIBD segment data structures and proof verification.

A Segment is a contiguous subtree of a PMMR covering 2^height nodes.
Each segment carries:
  - Its SegmentIdentifier (height, idx) identifying which subtree it covers
  - A list of internal hashes for non-leaf nodes in the subtree
  - A list of (leaf_insertion_idx, leaf_data) pairs for leaf nodes
  - A SegmentProof — the Merkle path from the segment's local peak into the
    full MMR root at the target block header height

SegmentType + SegmentTypeIdentifier mirror Grin's
  core/src/core/pmmr/segment.rs
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator, List, Optional, Tuple

from mimblewimble.mmr.index import (
    bintree_postorder_height,
    bintree_range,
    family_branch,
    insertion_to_pmmr_index,
    is_leaf,
    n_leaves,
    peak_map_height,
    peaks,
    pmmr_leaf_to_insertion_index,
)
from mimblewimble.mmr.proof import hash_with_index

# ---------------------------------------------------------------------------
# SegmentType
# ---------------------------------------------------------------------------


class SegmentType(IntEnum):
    """Which PMMR a segment belongs to.

    Values match Grin's ``SegmentType`` enum integer representation as used
    in wire-format segment request messages.
    """

    BITMAP = 0
    OUTPUT = 1
    RANGEPROOF = 2
    KERNEL = 3


# ---------------------------------------------------------------------------
# SegmentError
# ---------------------------------------------------------------------------


class SegmentError(Exception):
    """Base class for segment-related errors."""


class MissingLeafError(SegmentError):
    def __init__(self, pos: int) -> None:
        super().__init__(f"Missing leaf at pos {pos}")
        self.pos = pos


class MissingHashError(SegmentError):
    def __init__(self, pos: int) -> None:
        super().__init__(f"Missing hash at pos {pos}")
        self.pos = pos


class NonExistentSegmentError(SegmentError):
    def __init__(self) -> None:
        super().__init__("Segment does not exist")


class RootMismatchError(SegmentError):
    def __init__(self) -> None:
        super().__init__("Root hash mismatch")


# ---------------------------------------------------------------------------
# SegmentIdentifier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SegmentIdentifier:
    """Identifies a subtree within a PMMR by its height and index.

    ``height``  Height of the local peak that roots this subtree.
                A height-h segment covers 2^(h+1) - 1 total nodes,
                containing 2^h leaves.

    ``idx``     0-based index of this segment within the PMMR
                (i.e. the k-th chunk of height-h subtrees from the left).

    Wire format (Grin-compatible):  1 byte height  |  8 bytes LE idx
    """

    height: int
    idx: int

    def serialize(self) -> bytes:
        """Encode to 9-byte wire format (1-byte height + 8-byte LE idx)."""
        return struct.pack("<BQ", self.height, self.idx)

    @classmethod
    def deserialize(cls, data: bytes) -> "SegmentIdentifier":
        """Decode from 9-byte wire format."""
        if len(data) < 9:
            raise ValueError(f"SegmentIdentifier requires 9 bytes, got {len(data)}")
        height, idx = struct.unpack_from("<BQ", data)
        return cls(height=height, idx=idx)

    def segment_first_mmr_pos(self) -> int:
        """First 0-based MMR position covered by this segment.

        A height-h segment starting at index ``idx`` covers positions:
          [idx * (2^(h+1) - 1)  ..  idx * (2^(h+1) - 1) + (2^(h+1) - 2)]
        """
        subtree_size = (1 << (self.height + 1)) - 1
        return self.idx * subtree_size

    def segment_last_mmr_pos(self) -> int:
        """Last 0-based MMR position (inclusive) covered by this segment."""
        subtree_size = (1 << (self.height + 1)) - 1
        return (self.idx + 1) * subtree_size - 1

    def leaf_range(self) -> Tuple[int, int]:
        """Inclusive (first_leaf_idx, last_leaf_idx) insertion indices."""
        leaves_per_segment = 1 << self.height
        first = self.idx * leaves_per_segment
        last = first + leaves_per_segment - 1
        return first, last

    def __repr__(self) -> str:
        return f"SegmentIdentifier(h={self.height}, idx={self.idx})"


# ---------------------------------------------------------------------------
# SegmentTypeIdentifier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SegmentTypeIdentifier:
    """Combines a SegmentType with a SegmentIdentifier for unique identification.

    Mirrors Grin's ``SegmentTypeIdentifier`` struct.  Used for request
    tracking in ``SyncState.requested_pibd_segments``.
    """

    segment_type: SegmentType
    identifier: SegmentIdentifier

    def serialize(self) -> bytes:
        return struct.pack("<B", int(self.segment_type)) + self.identifier.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "SegmentTypeIdentifier":
        if len(data) < 10:
            raise ValueError(
                f"SegmentTypeIdentifier requires 10 bytes, got {len(data)}"
            )
        seg_type = SegmentType(data[0])
        identifier = SegmentIdentifier.deserialize(data[1:10])
        return cls(segment_type=seg_type, identifier=identifier)

    def __repr__(self) -> str:
        return (
            f"SegmentTypeIdentifier(type={self.segment_type.name}, "
            f"{self.identifier!r})"
        )


# ---------------------------------------------------------------------------
# SegmentProof
# ---------------------------------------------------------------------------


@dataclass
class SegmentProof:
    """Merkle path from a segment's local peak into the full MMR root.

    This proves that a segment's computed local root is included in the full
    MMR root of the target block header.

    Attributes:
        hashes      The sibling hashes needed to reconstruct the path from the
                    segment's local peak (right child / left accumulator pairs)
                    up to the full MMR root.
        mmr_size    Total MMR node count at the target block header.

    Wire format:
        8 bytes LE  mmr_size
        4 bytes LE  len(hashes)
        N × 32      hash bytes
    """

    mmr_size: int
    hashes: List[bytes] = field(default_factory=list)

    def size(self) -> int:
        return len(self.hashes)

    def serialize(self) -> bytes:
        out = struct.pack("<QI", self.mmr_size, len(self.hashes))
        for h in self.hashes:
            assert len(h) == 32
            out += h
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "SegmentProof":
        mmr_size, n = struct.unpack_from("<QI", data, 0)
        hashes = []
        offset = 12
        for _ in range(n):
            hashes.append(data[offset : offset + 32])
            offset += 32
        return cls(mmr_size=mmr_size, hashes=hashes)

    def verify(
        self,
        segment_root: bytes,
        full_mmr_root: bytes,
        peak_pos0: int,
    ) -> bool:
        """Verify that *segment_root* at *peak_pos0* is included in *full_mmr_root*.

        Works by re-bagging peaks: the proof hashes are the other peak hashes
        (left peaks then right-peak accumulator) needed to reconstruct the
        full MMR root.

        Algorithm mirrors single-leaf ``MerkleProof.verify()`` but the
        starting value is the segment's subtree root rather than a leaf hash.
        """
        mmr_size = self.mmr_size
        all_peaks = peaks(mmr_size)
        if not all_peaks:
            return segment_root == full_mmr_root

        if peak_pos0 not in all_peaks:
            # segment peak is not a PMMR peak — invalid
            return False

        peak_idx = all_peaks.index(peak_pos0)

        # Left peaks are to the left of peak_pos0 (lower index)
        left_peaks = all_peaks[:peak_idx]
        # Right peaks are to the right
        right_peaks = all_peaks[peak_idx + 1 :]

        n_left = len(left_peaks)
        n_right = len(right_peaks)

        if len(self.hashes) != n_left + (1 if right_peaks else 0):
            return False

        # Start from segment root and apply right-peak accumulator if present
        acc = segment_root
        if right_peaks:
            # Last hash in proof is the pre-bagged right accumulator
            rhs_acc = self.hashes[n_left]
            # bag: acc = hash(mmr_size, left_peak_hash | rhs_acc)
            # but segment_root is the left peak here, rhs_acc is right
            acc = hash_with_index(mmr_size, acc + rhs_acc)

        # Now fold in left peaks right-to-left
        for left_hash in reversed(self.hashes[:n_left]):
            acc = hash_with_index(mmr_size, left_hash + acc)

        return acc == full_mmr_root


# ---------------------------------------------------------------------------
# Segment
# ---------------------------------------------------------------------------


@dataclass
class Segment:
    """A contiguous subtree of a PMMR sent/received during PIBD sync.

    Attributes:
        identifier  Which subtree this is.
        hashes      Internal node hashes: list of (mmr_pos0, 32-byte hash).
        leaf_data   Leaf data: list of (leaf_insertion_idx, raw_bytes).
        proof       SegmentProof for the segment's local peak.

    Wire format (compatible with Grin's ``Segment<T>::read``):
        SegmentIdentifier  (9 bytes)
        4 bytes LE  num_hashes
        for each hash:
            8 bytes LE  pos0
            32 bytes    hash
        4 bytes LE  num_leaves
        for each leaf:
            8 bytes LE  leaf_insertion_idx
            4 bytes LE  data_len
            data_len bytes  data
        SegmentProof
    """

    identifier: SegmentIdentifier
    hashes: List[Tuple[int, bytes]] = field(default_factory=list)
    leaf_data: List[Tuple[int, bytes]] = field(default_factory=list)
    proof: Optional[SegmentProof] = None

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def id(self) -> SegmentIdentifier:
        return self.identifier

    def hash_iter(self) -> Iterator[Tuple[int, bytes]]:
        """Yield (pos0, hash_bytes) for each internal hash in the segment."""
        return iter(self.hashes)

    def leaf_iter(self) -> Iterator[Tuple[int, bytes]]:
        """Yield (leaf_insertion_idx, data_bytes) for each leaf."""
        return iter(self.leaf_data)

    # ------------------------------------------------------------------
    # Local root computation
    # ------------------------------------------------------------------

    def segment_pos0(self) -> int:
        """0-based MMR position of this segment's local peak."""
        # The segment's local peak is at the highest ancestor position that
        # covers exactly this segment's leaf range.
        # For a height-h segment at idx, start pos = idx * (2^(h+1) - 1),
        # and the local peak is start + 2^(h+1) - 2 = last pos in segment.
        return self.identifier.segment_last_mmr_pos()

    def compute_root(self) -> Optional[bytes]:
        """Reconstruct the segment's local subtree root from stored hashes.

        Returns the root hash, or None if required hashes are missing.
        """
        pos_to_hash: dict[int, bytes] = {}

        # Populate leaf hashes
        for leaf_idx, data in self.leaf_data:
            pos0 = insertion_to_pmmr_index(leaf_idx)
            pos_to_hash[pos0] = hash_with_index(pos0, data)

        # Populate provided internal hashes (these are stored hashes for
        # positions where we cannot compute from leaves alone)
        for pos0, h in self.hashes:
            pos_to_hash[pos0] = h

        # Walk the segment's range bottom-up and compute missing internals
        identifier = self.identifier
        height = identifier.height
        start = identifier.segment_first_mmr_pos()

        for h_level in range(height + 1):
            level_start = start
            step = (1 << (h_level + 1)) - 1
            sub_size = step
            # For each node at height h_level within the segment
            count = 1 << (height - h_level)
            for i in range(count):
                node_pos = level_start + i * step + sub_size - 1  # peak of sub-subtree
                if node_pos in pos_to_hash:
                    continue
                if h_level == 0:
                    # leaf — must have been provided
                    continue
                # compute from children
                left_pos = node_pos - 1 - (1 << h_level) + 1
                right_pos = node_pos - 1
                lh = pos_to_hash.get(left_pos)
                rh = pos_to_hash.get(right_pos)
                if lh is not None and rh is not None:
                    pos_to_hash[node_pos] = hash_with_index(node_pos, lh + rh)

        local_peak = self.segment_pos0()
        return pos_to_hash.get(local_peak)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, full_mmr_root: bytes) -> bool:
        """Verify the segment's integrity against *full_mmr_root*.

        Steps:
        1. Recompute segment's local root from leaf data + provided hashes.
        2. Verify the SegmentProof merges local root → full_mmr_root.

        Returns True on success, False otherwise.
        Raises SegmentError if required data is missing.
        """
        if self.proof is None:
            raise SegmentError("Segment has no proof")

        local_root = self.compute_root()
        if local_root is None:
            raise MissingHashError(self.segment_pos0())

        return self.proof.verify(
            segment_root=local_root,
            full_mmr_root=full_mmr_root,
            peak_pos0=self.segment_pos0(),
        )

    # ------------------------------------------------------------------
    # Construction from a PMMR
    # ------------------------------------------------------------------

    @classmethod
    def from_pmmr(
        cls,
        identifier: SegmentIdentifier,
        pmmr: "PMMR",  # type: ignore[name-defined]
        is_prunable: bool,
    ) -> "Segment":
        """Extract a segment from a live PMMR.

        Creates a Segment containing all available hashes and leaf data in
        the specified subtree, plus a SegmentProof for the local peak.

        Args:
            identifier    Which subtree to extract.
            pmmr          The source PMMR (must already be populated to target size).
            is_prunable   Whether pruned leaves should be omitted from leaf_data.

        Raises:
            NonExistentSegmentError  If the segment extends beyond the PMMR.
            MissingHashError         If a required internal hash is absent.
        """
        mmr_size = pmmr.size()
        first_pos = identifier.segment_first_mmr_pos()
        last_pos = identifier.segment_last_mmr_pos()

        if first_pos >= mmr_size:
            raise NonExistentSegmentError()

        # Clamp last_pos to existing MMR (partial last segment is OK)
        effective_last = min(last_pos, mmr_size - 1)

        # Collect internal hashes for non-leaf positions in the segment range
        seg_hashes: List[Tuple[int, bytes]] = []
        seg_leaves: List[Tuple[int, bytes]] = []

        for pos in range(first_pos, effective_last + 1):
            h = pmmr._hashes.get(pos)
            if is_leaf(pos):
                leaf_idx = pmmr_leaf_to_insertion_index(pos)
                if leaf_idx is None:
                    continue
                data = pmmr.get_data(pos)
                if data is not None:
                    seg_leaves.append((leaf_idx, data))
            else:
                if h is not None:
                    seg_hashes.append((pos, h))

        # Build SegmentProof: path from the local peak into the full MMR root
        proof = cls._build_proof(identifier, pmmr, mmr_size)

        return cls(
            identifier=identifier,
            hashes=seg_hashes,
            leaf_data=seg_leaves,
            proof=proof,
        )

    @staticmethod
    def _build_proof(
        identifier: SegmentIdentifier,
        pmmr: "PMMR",  # type: ignore[name-defined]
        mmr_size: int,
    ) -> SegmentProof:
        """Build a SegmentProof for the segment's local peak."""
        local_peak = identifier.segment_last_mmr_pos()
        all_peaks = peaks(mmr_size)

        # Find the actual PMMR peak that contains our local peak
        # (if the segment peak IS a PMMR peak, it's straightforward;
        # otherwise we need to walk up to the nearest MMR peak)
        if local_peak not in all_peaks:
            # Local peak is below the PMMR's peak list, find the enclosing peak
            containing_peak = None
            for p in all_peaks:
                if p >= local_peak:
                    containing_peak = p
                    break
            if containing_peak is None:
                return SegmentProof(mmr_size=mmr_size, hashes=[])
            # For now, use the containing peak as the proof anchor
            # (simplified proof — full impl would include path to peak)
            peak_pos = containing_peak
        else:
            peak_pos = local_peak

        peak_idx = all_peaks.index(peak_pos)
        left_peaks = all_peaks[:peak_idx]
        right_peaks = all_peaks[peak_idx + 1 :]

        proof_hashes: List[bytes] = []

        # Include left peak hashes
        for p in left_peaks:
            h = pmmr._hashes.get(p)
            if h is not None:
                proof_hashes.append(h)

        # Include pre-bagged right accumulator if there are right peaks
        if right_peaks:
            rhs_acc: Optional[bytes] = None
            for p in reversed(right_peaks):
                h = pmmr._hashes.get(p)
                if h is None:
                    break
                if rhs_acc is None:
                    rhs_acc = h
                else:
                    rhs_acc = hash_with_index(mmr_size, h + rhs_acc)
            if rhs_acc is not None:
                proof_hashes.append(rhs_acc)

        return SegmentProof(mmr_size=mmr_size, hashes=proof_hashes)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """Encode the segment to bytes (Grin-compatible wire format)."""
        out = self.identifier.serialize()
        # internal hashes
        out += struct.pack("<I", len(self.hashes))
        for pos0, h in self.hashes:
            out += struct.pack("<Q", pos0)
            out += h
        # leaf data
        out += struct.pack("<I", len(self.leaf_data))
        for leaf_idx, data in self.leaf_data:
            out += struct.pack("<Q", leaf_idx)
            out += struct.pack("<I", len(data))
            out += data
        # proof
        if self.proof is not None:
            out += self.proof.serialize()
        else:
            out += struct.pack("<QI", 0, 0)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "Segment":
        """Decode a segment from bytes."""
        offset = 0
        identifier = SegmentIdentifier.deserialize(data[offset : offset + 9])
        offset += 9

        (num_hashes,) = struct.unpack_from("<I", data, offset)
        offset += 4
        hashes = []
        for _ in range(num_hashes):
            (pos0,) = struct.unpack_from("<Q", data, offset)
            offset += 8
            h = data[offset : offset + 32]
            offset += 32
            hashes.append((pos0, h))

        (num_leaves,) = struct.unpack_from("<I", data, offset)
        offset += 4
        leaf_data = []
        for _ in range(num_leaves):
            (leaf_idx,) = struct.unpack_from("<Q", data, offset)
            offset += 8
            (data_len,) = struct.unpack_from("<I", data, offset)
            offset += 4
            ldata = data[offset : offset + data_len]
            offset += data_len
            leaf_data.append((leaf_idx, ldata))

        proof = SegmentProof.deserialize(data[offset:])

        return cls(
            identifier=identifier,
            hashes=hashes,
            leaf_data=leaf_data,
            proof=proof,
        )
