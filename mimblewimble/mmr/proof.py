"""
mimblewimble/mmr/proof.py

MerkleProof for a single leaf in a PMMR.

The proof format matches Grin's reference implementation:
  - path = [sibling hashes up to local peak] + [peak-bagging hashes]
  - verification re-hashes using the same ``hash_with_index`` scheme as PMMR

Wire format (compatible with Grin's ser/de):
  8-byte LE  mmr_size
  4-byte LE  path length (number of 32-byte hashes)
  N × 32     hash bytes
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from mimblewimble.mmr.index import (
    bintree_postorder_height,
    family_branch,
    is_left_sibling,
    peaks,
)

# ---------------------------------------------------------------------------
# Low-level hash primitive (shared with pmmr.py via import)
# ---------------------------------------------------------------------------


def hash_with_index(pos0: int, data: bytes) -> bytes:
    """Blake2b-256 of (pos0 as LE-uint64) ‖ data.

    This is the single hash primitive used throughout Grin's PMMR:
      - Leaf:   hash_with_index(leaf_pos0, leaf_serialized_bytes)
      - Parent: hash_with_index(parent_pos0, left_hash + right_hash)
      - Bagging: hash_with_index(mmr_size, left_peak_hash + right_accumulator)
    """
    prefix = pos0.to_bytes(8, "little")
    return hashlib.blake2b(prefix + data, digest_size=32).digest()


# ---------------------------------------------------------------------------
# MerkleProof
# ---------------------------------------------------------------------------


@dataclass
class MerkleProof:
    """Merkle inclusion proof for a leaf in a PMMR.

    Attributes:
        mmr_size  Total MMR node count at the time the proof was generated.
        path      Ordered list of 32-byte hashes:
                    [siblings from leaf → local peak] +
                    [hashes needed to bag the peaks (left peaks, then
                     the pre-bagged right-of-peak accumulator if any)]
    """

    mmr_size: int
    path: List[bytes] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """Encode to Grin wire format."""
        out = struct.pack("<Q", self.mmr_size)
        out += struct.pack("<I", len(self.path))
        for h in self.path:
            assert len(h) == 32
            out += h
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "MerkleProof":
        (mmr_size,) = struct.unpack_from("<Q", data, 0)
        (n,) = struct.unpack_from("<I", data, 8)
        path = []
        offset = 12
        for _ in range(n):
            path.append(data[offset : offset + 32])
            offset += 32
        return cls(mmr_size=mmr_size, path=path)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, leaf_hash: bytes, leaf_pos0: int, root: bytes) -> bool:
        """Return True iff this proof establishes *leaf_hash* at *leaf_pos0* in the root.

        The algorithm mirrors Grin's ``MerkleProof::verify``:
          1. Walk ``family_branch(leaf_pos0, mmr_size)`` using the first
             ``len(branch)`` path entries as sibling hashes to reconstruct
             the local-peak hash.
          2. Use the remaining path entries to re-bag all peaks and check
             against *root*.
        """
        if not self.path and not peaks(self.mmr_size):
            return leaf_hash == root

        branch = family_branch(leaf_pos0, self.mmr_size)
        if len(self.path) < len(branch):
            return False

        # --- Step 1: re-hash up to local peak ---
        current_hash = leaf_hash
        current_pos = leaf_pos0

        for i, (parent_pos, sibling_pos) in enumerate(branch):
            sibling_hash = self.path[i]
            if is_left_sibling(current_pos):
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            current_hash = hash_with_index(parent_pos, combined)
            current_pos = parent_pos

        # current_hash is now the local peak hash; current_pos is the peak pos
        peak_pos = current_pos
        path_remainder = self.path[len(branch) :]

        # --- Step 2: bag all peaks ---
        all_peaks = peaks(self.mmr_size)
        if not all_peaks:
            return current_hash == root

        if peak_pos not in all_peaks:
            return False

        peak_idx = all_peaks.index(peak_pos)
        left_peak_count = peak_idx
        if len(path_remainder) < left_peak_count:
            return False

        left_peak_hashes = path_remainder[:left_peak_count]
        remainder_after_left = path_remainder[left_peak_count:]

        has_right_peaks = peak_idx < (len(all_peaks) - 1)
        if has_right_peaks:
            if len(remainder_after_left) != 1:
                return False
            rhs_acc = remainder_after_left[0]
            acc: Optional[bytes] = hash_with_index(
                self.mmr_size, current_hash + rhs_acc
            )
        else:
            if len(remainder_after_left) != 0:
                return False
            acc = current_hash

        for ph in reversed(left_peak_hashes):
            acc = hash_with_index(self.mmr_size, ph + acc)

        return acc == root
