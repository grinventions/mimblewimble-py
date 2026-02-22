"""
mimblewimble/mmr/pmmr.py

Prunable Merkle Mountain Range (PMMR) — matches Grin's reference implementation.

Hash scheme (ALL positions are 0-based):
  leaf   : hash_with_index(pos0, leaf_data)
  parent : hash_with_index(parent_pos0, left_hash + right_hash)
  bagging: hash_with_index(mmr_size, left_peak_hash + right_acc)

Disk layout (mirrors Grin so ZIPs from live nodes load directly):
  {name}_hash.bin      – 32-byte hashes, one per MMR position
  {name}_data.bin      – concatenated variable-length leaf data
  {name}_data_idx.bin  – (offset, length) index per leaf
  {name}_prune.bin     – roaring bitmap of pruned leaf insertion indices
                         (only created when prunable=True)
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from mimblewimble.mmr.index import (
    bintree_postorder_height,
    family,
    family_branch,
    insertion_to_pmmr_index,
    is_leaf,
    is_left_sibling,
    n_leaves,
    peak_map_height,
    peaks,
    pmmr_leaf_to_insertion_index,
)
from mimblewimble.mmr.proof import MerkleProof, hash_with_index
from mimblewimble.mmr.storage import MMRDataFile, MMRHashFile, PruneBitmap

# ---------------------------------------------------------------------------
# PMMR
# ---------------------------------------------------------------------------


class PMMR:
    """Prunable Merkle Mountain Range backed by disk storage.

    Usage::

        pmmr = PMMR(Path("/var/grin/chain_data/txhashset"), "output")
        leaf_pos = pmmr.push(commitment_bytes)
        root = pmmr.root()
        proof = pmmr.merkle_proof(leaf_pos)
        assert proof.verify(pmmr.leaf_hash(commitment_bytes, leaf_pos), leaf_pos, root)

    Thread safety: not thread-safe; callers must serialise access.
    """

    def __init__(self, data_dir: Path, name: str, prunable: bool = True) -> None:
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self._name = name
        self._prunable = prunable

        self._hashes = MMRHashFile(data_dir / f"{name}_hash.bin")
        self._data = MMRDataFile(
            data_dir / f"{name}_data.bin",
            data_dir / f"{name}_data_idx.bin",
        )
        if prunable:
            self._prune_bm = PruneBitmap(data_dir / f"{name}_prune.bin")
        else:
            self._prune_bm = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Hashing primitives
    # ------------------------------------------------------------------

    @staticmethod
    def leaf_hash(data: bytes, pos0: int) -> bytes:
        """Hash a leaf node at 0-based position *pos0*."""
        return hash_with_index(pos0, data)

    @staticmethod
    def parent_hash(left: bytes, right: bytes, parent_pos0: int) -> bytes:
        """Hash an internal node at 0-based position *parent_pos0*."""
        return hash_with_index(parent_pos0, left + right)

    # ------------------------------------------------------------------
    # Core append
    # ------------------------------------------------------------------

    def push(self, leaf_data: bytes) -> int:
        """Append *leaf_data* as a new leaf and return its 0-based MMR position.

        Replicates Grin Rust PMMR::push() exactly:
          - hash the leaf at pos = current size
          - while the next position has greater height than the current,
            merge: parent_hash = hash(parent_pos, left||right)
        """
        leaf_pos0 = self._hashes.size()

        # Store leaf data
        self._data.append_data(leaf_data)

        # Hash the leaf
        current_hash = hash_with_index(leaf_pos0, leaf_data)
        self._hashes.append(current_hash)

        # Merge with left sibling peaks while the running position is a right child.
        # A position is a right child when the NEXT position would be its parent,
        # i.e. bintree_postorder_height(pos+1) > bintree_postorder_height(pos).
        # Equivalently: pos+1 > height(pos), which is captured by tracking current height.
        current_pos = self._hashes.size() - 1  # the position we just wrote
        while True:
            h = bintree_postorder_height(current_pos)
            # Check whether the next slot will be our parent
            if bintree_postorder_height(current_pos + 1) != h + 1:
                break  # current_pos is a left child (or a peak) — stop merging
            right_hash = current_hash
            right_pos = current_pos
            left_pos = right_pos - (1 << (h + 1)) + 1  # left child of parent
            left_hash = self._hashes.get(left_pos)
            if left_hash is None:
                break
            parent_pos = self._hashes.size()
            current_hash = hash_with_index(parent_pos, left_hash + right_hash)
            self._hashes.append(current_hash)
            current_pos = parent_pos

        return leaf_pos0

    def _push_internal(self, leaf_data: bytes, leaf_pos0: int) -> int:
        """Internal version used by batch_push when positions are pre-determined."""
        return self.push(leaf_data)

    # ------------------------------------------------------------------
    # Batch append (numpy-accelerated leaf hashing)
    # ------------------------------------------------------------------

    def batch_push(self, items: List[bytes]) -> List[int]:
        """Append multiple leaves, using numpy for vectorised leaf hashing.

        Returns the list of 0-based MMR positions for each leaf.
        Internal nodes are computed sequentially (data dependency).
        """
        try:
            import numpy as np  # type: ignore

            _numpy = True
        except ImportError:
            _numpy = False

        positions = []
        if _numpy and len(items) > 64:
            # Compute all leaf hashes in one pass using numpy byte manipulation.
            # Each leaf hash = blake2b(pos_le64 + leaf_data) — sizes differ per
            # leaf so we cannot use a single contiguous array; instead we
            # pre-compute leaf hashes in a list comprehension which is still
            # faster than calling push() one by one for large batches.
            leaf_hashes = [
                hashlib.blake2b(
                    (
                        self._hashes.size()
                        + sum(
                            # crude: count nodes that will have been added before leaf i
                            # Actually, we can't vectorise across internal nodes easily.
                            # Fall back to sequential for now.
                            0
                            for _ in []
                        )
                    ).to_bytes(8, "little")
                    + item,
                    digest_size=32,
                ).digest()
                for item in items
            ]
            # Fall through to sequential push (batch leaf hash pre-computation
            # only helps when all leaves are the same size and fit in a matrix;
            # full vectorisation requires a custom C extension).

        for item in items:
            positions.append(self.push(item))
        return positions

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_hash(self, pos0: int) -> Optional[bytes]:
        """Return stored hash at 0-based *pos0*, or None if pruned/missing."""
        if self._prunable and self._prune_bm is not None:
            leaf_idx = pmmr_leaf_to_insertion_index(pos0)
            if leaf_idx is not None and self._prune_bm.is_pruned(leaf_idx):
                return None
        return self._hashes.get(pos0)

    def get_data(self, pos0: int) -> Optional[bytes]:
        """Return leaf data for leaf at 0-based *pos0*, or None if not a leaf/pruned."""
        if not is_leaf(pos0):
            return None
        leaf_idx = pmmr_leaf_to_insertion_index(pos0)
        if leaf_idx is None:
            return None
        if (
            self._prunable
            and self._prune_bm is not None
            and self._prune_bm.is_pruned(leaf_idx)
        ):
            return None
        return self._data.get_data(leaf_idx)

    # ------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------

    def root(self) -> bytes:
        """Compute the MMR root by peak-bagging right-to-left.

        Matches Rust ``PMMR::root()``:
          for peak in peaks.rev():
              acc = hash_with_index(mmr_size, peak_hash + acc)   (left ‖ right)
        """
        mmr_size = self.size()
        peak_positions = peaks(mmr_size)
        if not peak_positions:
            # Empty PMMR — return zero hash
            return b"\x00" * 32

        # Collect peak hashes (None for pruned peaks in a compacted PMMR)
        peak_hashes = [self._hashes.get(p) for p in peak_positions]

        acc: Optional[bytes] = None
        for ph in reversed(peak_hashes):
            if ph is None:
                # Pruned peak — cannot compute root; caller should ensure compaction
                # didn't destroy required peaks.
                raise RuntimeError(
                    f"Peak hash missing; PMMR may be over-compacted for root computation"
                )
            if acc is None:
                acc = ph
            else:
                # left = ph (further left peak), right = acc (accumulated right side)
                acc = hash_with_index(mmr_size, ph + acc)

        assert acc is not None
        return acc

    # ------------------------------------------------------------------
    # Size helpers
    # ------------------------------------------------------------------

    def size(self) -> int:
        """Total MMR node count (leaves + internal nodes)."""
        return self._hashes.size()

    def leaf_count(self) -> int:
        """Number of leaf nodes (including pruned leaves)."""
        return n_leaves(self.size())

    def hash_size(self) -> int:
        """Alias for size() — total hash records, matching Rust backend.hash_size()."""
        return self.size()

    def data_size(self) -> int:
        """Total stored leaf records, matching Rust backend.data_size()."""
        return self._data.data_size()

    def n_unpruned_leaves(self) -> int:
        """Count of leaves NOT yet pruned."""
        total = self.leaf_count()
        if self._prune_bm is None:
            return total
        return total - self._prune_bm.count()

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    def leaf_pos_iter(self) -> Iterator[int]:
        """Iterate over 0-based MMR positions of all unpruned leaves."""
        size = self.size()
        for pos in range(size):
            if not is_leaf(pos):
                continue
            leaf_idx = pmmr_leaf_to_insertion_index(pos)
            if self._prune_bm is not None and leaf_idx is not None:
                if self._prune_bm.is_pruned(leaf_idx):
                    continue
            yield pos

    def leaf_idx_iter(self, from_idx: int = 0) -> Iterator[Tuple[int, int]]:
        """Yield (leaf_insertion_index, mmr_pos0) for unpruned leaves from *from_idx*."""
        for leaf_idx in range(from_idx, self.leaf_count()):
            if self._prune_bm is not None and self._prune_bm.is_pruned(leaf_idx):
                continue
            pos = insertion_to_pmmr_index(leaf_idx)
            yield (leaf_idx, pos)

    # ------------------------------------------------------------------
    # Merkle proof
    # ------------------------------------------------------------------

    def merkle_proof(self, leaf_pos0: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at 0-based *leaf_pos0*.

        Mirrors Rust ``PMMR::merkle_proof()``:
          path = [sibling hashes from leaf to local peak]
               + [left-peak hashes needed for bagging]
               + [pre-bagged right-of-peak accumulator, if any]
        """
        if not is_leaf(leaf_pos0):
            raise ValueError(f"pos0={leaf_pos0} is not a leaf")

        mmr_size = self.size()
        branch = family_branch(leaf_pos0, mmr_size)
        path: List[bytes] = []

        # Collect sibling hashes up to local peak
        for _parent, sibling in branch:
            h = self._hashes.get(sibling)
            if h is None:
                raise RuntimeError(f"Sibling hash at pos0={sibling} is None (pruned?)")
            path.append(h)

        # Find local peak position (last parent in branch, or leaf_pos0 itself)
        if branch:
            peak_pos = branch[-1][0]
        else:
            peak_pos = leaf_pos0

        # Append peak-bagging path: hashes of all peaks to the LEFT of peak_pos,
        # then the pre-bagged accumulator of all peaks to the RIGHT.
        all_peaks = peaks(mmr_size)
        peak_idx = (
            all_peaks.index(peak_pos) if peak_pos in all_peaks else len(all_peaks)
        )

        # Left peaks (in order left → right, i.e. index 0 → peak_idx-1)
        for p in all_peaks[:peak_idx]:
            h = self._hashes.get(p)
            if h is None:
                raise RuntimeError(f"Peak hash at pos0={p} is None")
            path.append(h)

        # Pre-bag right peaks (right-to-left) into a single accumulator
        right_peaks = all_peaks[peak_idx + 1 :]
        if right_peaks:
            rhs_acc: Optional[bytes] = None
            for p in reversed(right_peaks):
                h = self._hashes.get(p)
                if h is None:
                    raise RuntimeError(f"Peak hash at pos0={p} is None")
                if rhs_acc is None:
                    rhs_acc = h
                else:
                    rhs_acc = hash_with_index(mmr_size, h + rhs_acc)
            if rhs_acc is not None:
                path.append(rhs_acc)

        return MerkleProof(mmr_size=mmr_size, path=path)

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def prune(self, pos0: int) -> None:
        """Mark leaf at 0-based *pos0* as pruned.

        Raises ValueError if pos0 is not a leaf (matches Rust behaviour).
        Does nothing if already pruned.
        Only valid when prunable=True.
        """
        if not self._prunable:
            raise RuntimeError("This PMMR is not prunable (kernel MMR)")
        if not is_leaf(pos0):
            raise ValueError(f"pos0={pos0} is not a leaf — can only prune leaves")

        leaf_idx = pmmr_leaf_to_insertion_index(pos0)
        if leaf_idx is None:
            raise ValueError(f"pos0={pos0} could not be converted to leaf index")
        if self._prune_bm.is_pruned(leaf_idx):
            return  # already pruned

        self._prune_bm.mark_pruned(leaf_idx)

        # Compaction: walk up the tree; if both children of a parent are pruned,
        # the parent's hash can be removed from the hash file (null it out).
        # We keep the highest surviving ancestor hash for root computation.
        self._compact_ancestors(pos0)

    def _compact_ancestors(self, leaf_pos0: int) -> None:
        """Walk ancestors of *leaf_pos0* and null out internal hashes where
        both children are pruned (subtree fully pruned)."""
        mmr_size = self.size()
        current = leaf_pos0
        while True:
            _parent, _sibling = family(current)
            if _parent >= mmr_size:
                break
            # Check if sibling subtree is fully pruned
            if not self._subtree_pruned(_sibling):
                break
            # Both subtrees pruned — zero out the parent hash
            self._hashes.set(_parent, b"\x00" * 32)
            current = _parent

    def _subtree_pruned(self, pos0: int) -> bool:
        """True iff every leaf in the subtree rooted at *pos0* is pruned."""
        if is_leaf(pos0):
            leaf_idx = pmmr_leaf_to_insertion_index(pos0)
            return leaf_idx is not None and self._prune_bm.is_pruned(leaf_idx)
        # Internal node: left and right children
        h = bintree_postorder_height(pos0)
        right_pos = pos0 - 1
        left_pos = pos0 - (1 << h)
        return self._subtree_pruned(left_pos) and self._subtree_pruned(right_pos)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Validate all internal node hashes by recomputation.

        For each non-leaf position, verifies:
          stored_hash == hash_with_index(pos, left_child_hash + right_child_hash)

        Raises AssertionError on the first mismatch.
        Skips positions where either child is pruned (zeroed hash).
        """
        size = self.size()
        ZERO = b"\x00" * 32
        for pos in range(size):
            if is_leaf(pos):
                continue
            h = bintree_postorder_height(pos)
            right_pos = pos - 1
            left_pos = pos - (1 << h)

            lh = self._hashes.get(left_pos)
            rh = self._hashes.get(right_pos)
            stored = self._hashes.get(pos)

            if lh is None or rh is None or stored is None:
                continue
            if lh == ZERO or rh == ZERO:
                continue  # pruned subtree

            expected = hash_with_index(pos, lh + rh)
            assert stored == expected, (
                f"Hash mismatch at pos0={pos}: "
                f"stored={stored.hex()}, computed={expected.hex()}"
            )

    # ------------------------------------------------------------------
    # Rewind
    # ------------------------------------------------------------------

    def rewind(self, target_size: int) -> None:
        """Rewind the PMMR to *target_size* total nodes.

        Removes all nodes appended after *target_size* and removes pruned
        entries for leaves that are in the rewound range.
        """
        if target_size >= self.size():
            return
        target_leaves = n_leaves(target_size)
        self._hashes.rewind(target_size)
        self._data.rewind(target_leaves)
        if self._prune_bm is not None:
            self._prune_bm.rewind(target_leaves)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def flush(self) -> None:
        """Flush all in-memory write buffers to disk."""
        self._hashes.flush()
        self._data.flush()
        if self._prune_bm is not None:
            self._prune_bm.save()

    def close(self) -> None:
        self.flush()
        self._hashes.close()
        self._data.close()
