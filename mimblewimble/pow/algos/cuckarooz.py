from typing import List

from mimblewimble.pow.common import SipHashKeys, SipHashState

# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

EDGEBITS        = 29
NEDGES          = 1 << EDGEBITS
EDGEMASK        = NEDGES - 1

# ← most important difference from cuckaroom
NNODES          = 2 * NEDGES
NODEMASK        = NNODES - 1

PROOFSIZE       = 42
EDGE_BLOCK_BITS = 12
EDGE_BLOCK_SIZE = 1 << EDGE_BLOCK_BITS
EDGE_BLOCK_MASK = EDGE_BLOCK_SIZE - 1

# ────────────────────────────────────────────────
# Error codes
# ────────────────────────────────────────────────

POW_OK            = 0
POW_TOO_BIG       = 1
POW_TOO_SMALL     = 2
POW_NON_MATCHING  = 3
POW_BRANCH        = 4
POW_DEAD_END      = 5
POW_SHORT_CYCLE   = 6

POW_ERROR_MESSAGES = {
    POW_OK:           "POW_OK",
    POW_TOO_BIG:      "edge > EDGEMASK",
    POW_TOO_SMALL:    "edges not strictly increasing",
    POW_NON_MATCHING: "xor of all endpoints != 0",
    POW_BRANCH:       "branch (multiple matches for same endpoint)",
    POW_DEAD_END:     "no matching endpoint found",
    POW_SHORT_CYCLE:  "cycle shorter than PROOFSIZE",
}

# ────────────────────────────────────────────────
# Helper functions
# ────────────────────────────────────────────────

def cuckarooz_sipblock(keys: SipHashKeys, edge: int, buf: List[int]) -> int:
    """
    Fills buf with EDGE_BLOCK_SIZE siphash outputs
    Returns siphash output for the requested edge
    """
    edge0 = edge & ~EDGE_BLOCK_MASK          # round down to block start

    shs = SipHashState(keys)

    # Fill buffer with consecutive siphash outputs
    for i in range(EDGE_BLOCK_SIZE):
        shs.hash24(edge0 + i)
        buf[i] = shs.xor_lanes()

    # Backward XOR chain (differential form)
    for i in range(EDGE_BLOCK_MASK, 0, -1):
        buf[i-1] ^= buf[i]

    # Return the exact siphash value for this edge
    idx_in_block = edge & EDGE_BLOCK_MASK
    return buf[idx_in_block]


def verify_cuckarooz(edges: List[int], keys: SipHashKeys) -> int:
    """
    Verifies Cuckarooz proof
    Returns one of POW_xxx constants
    """

    if len(edges) != PROOFSIZE:
        return POW_TOO_SMALL   # actually wrong size, but we reuse constant

    # ─── Step 1: basic checks + collect u,v endpoints ─────────────────────

    xoruv = 0
    uv = [0] * (2 * PROOFSIZE)          # list of all 84 endpoints
    sips = [0] * EDGE_BLOCK_SIZE        # reusable buffer

    prev_edge = -1

    for n in range(PROOFSIZE):
        edge = edges[n]

        if edge > EDGEMASK:
            return POW_TOO_BIG

        if n > 0 and edge <= prev_edge:
            return POW_TOO_SMALL

        prev_edge = edge

        sip = cuckarooz_sipblock(keys, edge, sips)

        u = sip & NODEMASK
        v = (sip >> 32) & NODEMASK

        uv[2 * n]     = u
        uv[2 * n + 1] = v

        xoruv ^= u
        xoruv ^= v

    if xoruv != 0:
        return POW_NON_MATCHING

    # ─── Step 2: cycle following ─────────────────────────────────────────

    visited = [False] * (2 * PROOFSIZE)
    n = 0
    i = 0

    while True:
        visited[i] = True
        u_target = uv[i]

        j = -1
        count_matches = 0

        for k in range(2 * PROOFSIZE):
            if k == i:
                continue
            if uv[k] == u_target:
                count_matches += 1
                j = k

        if count_matches == 0:
            return POW_DEAD_END

        if count_matches > 1:
            return POW_BRANCH

        # move to the other endpoint of the found edge
        i = j ^ 1
        n += 1

        # we closed the cycle
        if i == 0:
            break

    # must use exactly PROOFSIZE edges
    if n != PROOFSIZE:
        return POW_SHORT_CYCLE

    return POW_OK

# ────────────────────────────────────────────────
# High-level validate function
# ────────────────────────────────────────────────

def cuckarooz_validate(
    proof_nonces: List[int],          # list of PROOFSIZE edge indices
    pre_pow_hash: bytes               # 32-byte blake2b(pre-pow-header)
) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, message: str)
    """

    if len(proof_nonces) != PROOFSIZE:
        return False, f"Invalid proof size (expected {PROOFSIZE}, got {len(proof_nonces)})"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckarooz(proof_nonces, keys)

    if result == POW_OK:
        return True, "POW_OK"

    msg = POW_ERROR_MESSAGES.get(result, f"Unknown error code {result}")
    return False, msg