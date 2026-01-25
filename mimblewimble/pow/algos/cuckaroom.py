from mimblewimble.pow.common import SipHashKeys, sipblock

from typing import List

EDGEBITS       = 29
NEDGES         = 1 << EDGEBITS
EDGEMASK       = NEDGES - 1
NNODES         = NEDGES
NODEMASK       = NNODES - 1

# Most common values in recent Cuckaroom implementations
PROOFSIZE       = 42         # number of edges in cycle
EDGE_BLOCK_BITS = 12         # very typical value
EDGE_BLOCK_SIZE = 1 << EDGE_BLOCK_BITS
EDGE_BLOCK_MASK = EDGE_BLOCK_SIZE - 1

# error codes
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
    POW_NON_MATCHING: "xor of u's != xor of v's",
    POW_BRANCH:       "branch (cycle with repeated node)",
    POW_DEAD_END:     "no matching outgoing edge found",
    POW_SHORT_CYCLE:  "cycle shorter than PROOFSIZE",
}

def cuckaroom_sipblock(keys: SipHashKeys, edge: int, buf: List[int]) -> int:
    edge0 = edge & ~EDGE_BLOCK_MASK
    for i in range(EDGE_BLOCK_SIZE):
        buf[i], _ = sipblock(keys, edge0 + i)
    for i in range(EDGE_BLOCK_MASK, 0, -1):
        buf[i - 1] ^= buf[i]
    return buf[edge & EDGE_BLOCK_MASK]

def verify_cuckaroom(edges: List[int], keys: SipHashKeys) -> int:
    xorfrom = 0
    xorto = 0
    sips = [0] * EDGE_BLOCK_SIZE
    from_node = [0] * PROOFSIZE
    to_node = [0] * PROOFSIZE
    visited = [False] * PROOFSIZE

    for n in range(PROOFSIZE):
        if edges[n] > EDGEMASK:
            return POW_TOO_BIG
        if n > 0 and edges[n] <= edges[n - 1]:
            return POW_TOO_SMALL

        edge = cuckaroom_sipblock(keys, edges[n], sips)
        from_node[n] = edge & EDGEMASK
        to_node[n] = (edge >> 32) & EDGEMASK
        xorfrom ^= from_node[n]
        xorto ^= to_node[n]
        visited[n] = False

    if xorfrom != xorto:
        return POW_NON_MATCHING

    n = 0
    i = 0
    while True:
        if visited[i]:
            return POW_BRANCH
        visited[i] = True

        nexti = 0
        while nexti < PROOFSIZE and from_node[nexti] != to_node[i]:
            nexti += 1
        if nexti == PROOFSIZE:
            return POW_DEAD_END

        i = nexti
        n += 1
        if i == 0:
            break

    return POW_OK if n == PROOFSIZE else POW_SHORT_CYCLE

def cuckaroom_validate(
    proof_nonces: List[int],          # list of 42 edge indices (nonces)
    pre_pow_hash: bytes               # 32-byte blake2b hash of pre-PoW header
) -> tuple[bool, str]:
    """
    Returns (True, "OK") or (False, error message)
    """

    if len(proof_nonces) != PROOFSIZE:
        return False, f"Invalid proof size: expected {PROOFSIZE}, got {len(proof_nonces)}"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckaroom(proof_nonces, keys)

    if result == POW_OK:
        return True, "POW_OK"

    msg = POW_ERROR_MESSAGES.get(result, f"Unknown error code {result}")
    return False, msg