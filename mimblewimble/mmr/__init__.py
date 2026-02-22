"""
mimblewimble/mmr/__init__.py

Public API for the MMR/PMMR/TxHashSet subsystem.
"""

from mimblewimble.mmr.index import (
    # 1-based legacy index (used by blockchain.py)
    MMRIndex,
    # 0-based helpers (match Grin Rust reference)
    bintree_leftmost,
    bintree_postorder_height,
    bintree_range,
    bintree_rightmost,
    family,
    family_branch,
    insertion_to_pmmr_index,
    is_leaf,
    is_left_sibling,
    n_leaves,
    peak_map_height,
    peaks,
    pmmr_leaf_to_insertion_index,
    round_up_to_leaf_pos,
)
from mimblewimble.mmr.proof import MerkleProof, hash_with_index
from mimblewimble.mmr.pmmr import PMMR
from mimblewimble.mmr.txhashset import (
    TxHashSet,
    TxHashSetError,
    RootMismatchError,
    SizeMismatchError,
)
from mimblewimble.mmr.sync import TxHashSetSync

__all__ = [
    # Legacy 1-based index
    "MMRIndex",
    # 0-based position helpers
    "peak_map_height",
    "n_leaves",
    "insertion_to_pmmr_index",
    "pmmr_leaf_to_insertion_index",
    "bintree_postorder_height",
    "is_leaf",
    "is_left_sibling",
    "family",
    "family_branch",
    "peaks",
    "bintree_range",
    "bintree_leftmost",
    "bintree_rightmost",
    "round_up_to_leaf_pos",
    # Hashing
    "hash_with_index",
    # Core classes
    "MerkleProof",
    "PMMR",
    "TxHashSet",
    "TxHashSetSync",
    # Exceptions
    "TxHashSetError",
    "RootMismatchError",
    "SizeMismatchError",
]
