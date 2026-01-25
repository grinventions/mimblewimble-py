from typing import List

from mimblewimble.pow.common import SipHashState, SipHashKeys, PROOFSIZE

PROOFSIZE = 42         # number of edges in cycle

POW_OK            = 0
POW_TOO_BIG       = 1
POW_TOO_SMALL     = 2
POW_NON_MATCHING  = 3
POW_BRANCH        = 4
POW_DEAD_END      = 5
POW_SHORT_CYCLE   = 6

POW_ERROR_MESSAGES = {
    POW_OK:           "POW_OK",
    POW_TOO_BIG:      "edge > edgeMask",
    POW_TOO_SMALL:    "edges not strictly increasing",
    POW_NON_MATCHING: "xor0 | xor1 != 0",
    POW_BRANCH:       "multiple matches for same endpoint (branch)",
    POW_DEAD_END:     "no matching endpoint found",
    POW_SHORT_CYCLE:  "cycle length != PROOFSIZE",
}

def sipnode(
    keys,               # SipHashKeys
    edge: int,
    uorv: int,          # 0 or 1
    edge_mask: int
) -> int:
    """
    Compute one endpoint (u or v) of an edge
    In Cuckatoo: siphash(2*edge + uorv)
    """
    shs = SipHashState(keys)
    # hash24 = absorb 3 × 8 bytes = 24 bytes
    shs.hash24(2 * edge + uorv)
    return shs.xor_lanes() & edge_mask

def verify_cuckatoo(
    edges: List[int],
    keys,               # SipHashKeys
    edge_bits: int
) -> int:
    """
    Verifies Cuckatoo proof (variable edgeBits version)
    Returns POW_OK or error code
    """

    if len(edges) != PROOFSIZE:
        return POW_TOO_SMALL

    num_edges  = 1 << edge_bits
    edge_mask  = num_edges - 1

    xor0 = xor1 = (PROOFSIZE // 2) & 1   # parity initialization
    endpoints = [0] * (2 * PROOFSIZE)    # u0,v0, u1,v1, ...

    # Phase 1: extract endpoints + xor check
    for i in range(PROOFSIZE):
        edge = edges[i]

        if edge > edge_mask:
            return POW_TOO_BIG

        if i > 0 and edge <= edges[i - 1]:
            return POW_TOO_SMALL

        u = sipnode(keys, edge, 0, edge_mask)
        v = sipnode(keys, edge, 1, edge_mask)

        endpoints[2 * i]     = u
        endpoints[2 * i + 1] = v

        xor0 ^= u
        xor1 ^= v

    if xor0 | xor1:
        return POW_NON_MATCHING

    # Phase 2: cycle following (compare >>1, i.e. ignore partition bit)
    n = 0
    i = 0

    while True:
        current = endpoints[i] >> 1   # ignore partition bit

        j = None
        k = (i + 2) % (2 * PROOFSIZE)

        while k != i:
            if (endpoints[k] >> 1) == current:
                if j is not None:
                    return POW_BRANCH
                j = k
            k = (k + 2) % (2 * PROOFSIZE)

        if j is None or endpoints[j] == endpoints[i]:
            return POW_DEAD_END

        next_i = j ^ 1
        n += 1

        if next_i == 0:
            break

        i = next_i

    return POW_OK if n == PROOFSIZE else POW_SHORT_CYCLE

def cuckatoo_validate(
    proof_nonces: List[int],
    pre_pow_hash: bytes, # blake2b(pre-pow-header)
    edge_bits: int       # usually 29, 31, sometimes variable
) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, message: str)
    """
    if len(proof_nonces) != PROOFSIZE:
        return False, f"Invalid proof size (expected {PROOFSIZE}, got {len(proof_nonces)})"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckatoo(proof_nonces, keys, edge_bits)

    if result == POW_OK:
        return True, "POW_OK"

    msg = POW_ERROR_MESSAGES.get(result, f"Unknown error {result}")
    return False, msg