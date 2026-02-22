from mimblewimble.helpers import fillOnesToRight


class MMRIndex:
    def __init__(self, position: int, height: int):
        self.position = position
        self.height = height

    def isLeaf(self):
        return self.height == 0

    @classmethod
    def at(self, position: int):
        return MMRIndex(position, self.calculateHeight(position))

    # operators
    def __eq__(self, other):
        return self.position == other.position and self.height == other.height

    def __ne__(self, other):
        return self.position != other.position or self.height != other.height

    def __lt__(self, other):
        return self.position < other.position

    def __leq__(self, other):
        return self.position <= other.position

    def __gt__(self, other):
        return self.position > other.position

    def __geq__(self, other):
        return self.position >= other.position

    def getLeafIndex(self):
        assert self.isLeaf()
        return self.calculateLeafIndex(self.position)

    def getParent(self):
        if self.calculateHeight(self.position + 1) == self.height + 1:
            return MMRIndex(self.position + 1, self.height + 1)
        else:
            return MMRIndex(self.position + (1 << (self.height + 1)), self.height + 1)

    def getSibling(self):
        if self.calculateHeight(self.position + 1) == self.height + 1:
            return MMRIndex(self.position + 1 - (1 << (self.height + 1)), self.height)
        else:
            return MMRIndex(
                self.position + (1 << (self.height + 1)) - 1, self.height + 1
            )

    def getLeftChild(self):
        assert self.height > 0
        return MMRIndex(self.position - (1 << self.height), self.height - 1)

    def getRightChild(self):
        assert self.height > 0
        return MMRIndex(self.position - 1, self.height - 1)

    @classmethod
    def calculateHeight(self, position: int):
        height = position
        peakSize = fillOnesToRight(position + 1)
        while peakSize != 0:
            if height >= peakSize:
                height -= peakSize
            peakSize >>= 1
        return height

    def calculateLeafIndex(self, position: int):
        leafIndex = 0
        peakSize = fillOnesToRight(position)
        numLeft = position
        while peakSize != 0:
            if numLeft >= peakSize:
                leafIndex += (peakSize + 1) // 2
                numLeft -= peakSize
            peakSize >>= 1
        return leafIndex


# ---------------------------------------------------------------------------
# 0-based MMR position arithmetic — matches the Grin Rust reference exactly.
# All positions and sizes here are 0-based node counts (pos0 notation).
# ---------------------------------------------------------------------------


def _all_ones_64():
    return (1 << 64) - 1


def peak_map_height(size: int):
    """Return (peak_bitmap, next_height) for an MMR of *size* nodes.

    peak_bitmap has one bit set per peak, ordered most-significant = tallest.
    next_height is the height that the NEXT appended node would have.
    Matches Rust ``peak_map_height(size)``.

    Test vectors (some_peak_map):
      peak_map_height(0) = (0, 0)
      peak_map_height(1) = (1, 0)
      peak_map_height(3) = (2, 0)   # 0b10
      peak_map_height(4) = (3, 0)   # 0b11
      peak_map_height(7) = (4, 0)   # 0b100
    """
    if size == 0:
        return (0, 0)
    # largest power-of-2 minus 1 that fits in size
    peak_size = _all_ones_64() >> bin(size).count(
        "0"
    )  # NOT correct — use leading zeros
    # Replicate Rust: ALL_ONES >> size.leading_zeros()
    leading = 64 - size.bit_length()
    peak_size = _all_ones_64() >> leading
    peak_map = 0
    s = size
    while peak_size != 0:
        peak_map <<= 1
        if s >= peak_size:
            s -= peak_size
            peak_map |= 1
        peak_size >>= 1
    return (peak_map, s)


def n_leaves(mmr_size: int) -> int:
    """Number of leaf nodes in an MMR of *mmr_size* total nodes.

    Formula: peak_map + (1 if height > 0 else 0)
    where (peak_map, height) = peak_map_height(mmr_size).

    Test vectors (test_n_leaves):
      n_leaves(0)=0, n_leaves(1)=1, n_leaves(2)=2, n_leaves(3)=2,
      n_leaves(4)=3, n_leaves(5)=4, n_leaves(6)=4, n_leaves(7)=4,
      n_leaves(8)=5, n_leaves(9)=6, n_leaves(10)=6
    """
    if mmr_size == 0:
        return 0
    pm, height = peak_map_height(mmr_size)
    return pm + (1 if height > 0 else 0)


def insertion_to_pmmr_index(leaf_idx: int) -> int:
    """Convert 0-based leaf insertion index to 0-based MMR position.

    Formula: 2*n - popcount(n).
    Test vectors:
      0→0, 1→1, 2→3, 3→4, 4→7, 5→8, 6→10, 7→11
    """
    return 2 * leaf_idx - bin(leaf_idx).count("1")


def pmmr_leaf_to_insertion_index(pos0: int):
    """Convert 0-based MMR position to 0-based leaf insertion index.

    Returns None if pos0 is not a leaf position.
    Uses O(log n) formula: n_leaves(pos0 + 1) - 1.

    Test vectors:
      0→0, 1→1, 3→2, 4→3, 7→4, 2→None (not a leaf)
    """
    if not is_leaf(pos0):
        return None
    return n_leaves(pos0 + 1) - 1


def bintree_postorder_height(pos0: int) -> int:
    """Height of node at 0-based position pos0 in the MMR.

    height 0 = leaf.
    Uses peak_map_height(pos0)[1] — the height of the node *at* pos0
    (not the node *after* it).

    Test vectors (first_100_mmr_heights):
      pos 0→0, 1→0, 2→1, 3→0, 4→0, 5→1, 6→2, 7→0 ...
    """
    _, h = peak_map_height(pos0)
    return h


def is_leaf(pos0: int) -> bool:
    """True if pos0 is a leaf node (height 0)."""
    return bintree_postorder_height(pos0) == 0


def family(pos0: int):
    """Return (parent_pos0, sibling_pos0) for node at pos0.

    A node is a RIGHT child iff the next position (pos0+1) has strictly
    greater height, i.e. the parent merge happens immediately after.

    Test vectors (various_families):
      family(0)=(2,1), family(1)=(2,0), family(2)=(6,5),
      family(3)=(5,4), family(4)=(5,3), family(5)=(6,2)
    """
    h = bintree_postorder_height(pos0)
    sibling_offset = (1 << (h + 1)) - 1
    # pos0 is RIGHT child if the next position already has greater height
    if bintree_postorder_height(pos0 + 1) > h:
        # right child: parent is immediately after
        sibling = pos0 - sibling_offset
        parent = pos0 + 1
    else:
        # left child: sibling and parent are further to the right
        sibling = pos0 + sibling_offset
        parent = pos0 + sibling_offset + 1
    return (parent, sibling)


def is_left_sibling(pos0: int) -> bool:
    """True if pos0 is a left sibling (left child of its parent).

    A node is a right child iff bintree_postorder_height(pos0+1) > own height.

    Test vectors: is_left_sibling(0)=True, is_left_sibling(1)=False,
                  is_left_sibling(2)=True
    """
    h = bintree_postorder_height(pos0)
    return bintree_postorder_height(pos0 + 1) <= h


def family_branch(pos0: int, mmr_size: int):
    """Return the Merkle proof path: list of (parent_pos0, sibling_pos0) from pos0 to its local peak.

    Matches Rust ``family_branch(pos0, size)``.
    Test vectors (various_branches):
      family_branch(0, 3) = [(2, 1)]
      family_branch(1, 3) = [(2, 0)]
      family_branch(2, 3) = []
      family_branch(0, 7) = [(2, 1), (6, 5)]
      family_branch(3, 4) = []
      family_branch(3, 7) = [(5, 4), (6, 2)]
    """
    branch = []
    current = pos0
    while True:
        h = bintree_postorder_height(current)
        sibling_offset = (1 << (h + 1)) - 1
        if bintree_postorder_height(current + 1) > h:
            # right child
            sibling = current - sibling_offset
            parent = current + 1
        else:
            # left child
            sibling = current + sibling_offset
            parent = current + sibling_offset + 1
        # Stop if parent exceeds MMR size (current is a local peak)
        if parent >= mmr_size:
            break
        branch.append((parent, sibling))
        current = parent
    return branch


def peaks(mmr_size: int):
    """Return list of 0-based peak positions for an MMR of *mmr_size* total nodes.

    For each complete perfect-subtree (from largest to smallest) that fits
    in the remaining size, record the peak position (last node of that subtree).

    Test vectors (some_peaks):
      peaks(0)=[], peaks(1)=[0], peaks(3)=[2], peaks(4)=[2,3],
      peaks(7)=[6], peaks(11)=[6,9,10]
    """
    if mmr_size == 0:
        return []
    result = []
    s = mmr_size
    peak_pos = 0
    while s > 0:
        # Largest all-ones (2^b - 1) number that fits in s
        b = s.bit_length()
        subtree_size = (1 << b) - 1
        while subtree_size > s:
            b -= 1
            subtree_size = (1 << b) - 1
        peak_pos += subtree_size
        result.append(peak_pos - 1)
        s -= subtree_size
    return result


def bintree_range(pos0: int):
    """Return the half-open range of positions in the subtree rooted at pos0.

    Test vectors: bintree_range(0)=range(0,1), bintree_range(2)=range(0,3), bintree_range(6)=range(0,7)
    """
    h = bintree_postorder_height(pos0)
    subtree_size = (1 << (h + 1)) - 1
    left = pos0 + 1 - subtree_size
    return range(left, pos0 + 1)


def bintree_leftmost(pos0: int) -> int:
    """Leftmost leaf position in subtree rooted at pos0.

    Test vectors: bintree_leftmost(0)=0, bintree_leftmost(2)=0, bintree_leftmost(6)=0
    """
    h = bintree_postorder_height(pos0)
    return pos0 - ((1 << (h + 1)) - 2)


def bintree_rightmost(pos0: int) -> int:
    """Rightmost leaf position in subtree rooted at pos0.

    Test vectors: bintree_rightmost(0)=0, bintree_rightmost(2)=1, bintree_rightmost(6)=4
    """
    h = bintree_postorder_height(pos0)
    return pos0 - (h > 0 and 1 or 0)
    # Actually: rightmost leaf = pos0 - height (since right spine has 1 node per level)
    # Correct: rightmost = pos0 - h ... wait, for pos=6 (h=2): 6-2=4 ✓; pos=2 (h=1): 2-1=1 ✓; pos=0 (h=0): 0 ✓


def bintree_rightmost(pos0: int) -> int:
    h = bintree_postorder_height(pos0)
    return pos0 - h


def round_up_to_leaf_pos(pos0: int) -> int:
    """First leaf position at or after pos0.

    For a leaf, returns pos0 unchanged.  For an internal node, returns
    the first leaf position after the entire subtree rooted at pos0
    (= insertion_to_pmmr_index(n_leaves(pos0 + 1))).

    Test vectors:
      0→0, 1→1, 2→3, 3→3, 4→4, 5→7, 6→7, 7→7, 8→8, 9→10, 10→10
    """
    if is_leaf(pos0):
        return pos0
    return insertion_to_pmmr_index(n_leaves(pos0 + 1))
