from typing import List

from mimblewimble.pow.common import siphash_block
from mimblewimble.pow.common import SipHashKeys
from mimblewimble.pow.common import PROOFSIZE, EDGE_MASK, EDGEBITS
from mimblewimble.pow.common import EPoWStatus

NNODES    = 1 << EDGEBITS # ← Cuckarooz: monopartite
NEDGES    = 1 << EDGEBITS
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1

def verify_cuckarooz(proof: List[int], sip_keys: SipHashKeys) -> int:
    uvs = [0] * (2 * PROOFSIZE)          # flattened: u0,v0, u1,v1, ...
    xor_all = 0

    # 1. Basic checks + extract endpoints
    for i in range(PROOFSIZE):
        nonce = proof[i]

        if nonce > EDGE_MASK:
            return EPoWStatus.POW_TOO_BIG

        if i > 0 and nonce <= proof[i-1]:
            return EPoWStatus.POW_NOT_ASCENDING

        edge = siphash_block(sip_keys, nonce, 21, xor_all=True)
        u = edge & NODE_MASK
        v = (edge >> 32) & NODE_MASK

        uvs[2 * i]     = u
        uvs[2 * i + 1] = v
        xor_all ^= u ^ v

    if xor_all != 0:
        return EPoWStatus.POW_NON_MATCHING

    # 2. Cycle detection – Grin-style linked-list walk (undirected)
    MASK = 63   # 2⁶-1 — sufficient for 42 edges

    head = [2 * PROOFSIZE] * (MASK + 1)
    prev = [0] * (2 * PROOFSIZE)

    # Build reverse linked lists over **all** endpoints
    for n in range(2 * PROOFSIZE):
        bits = uvs[n] & MASK
        prev[n] = head[bits]
        head[bits] = n

    # Close the lists into circular chains
    for n in range(2 * PROOFSIZE):
        bits = uvs[n] & MASK
        if prev[n] == 2 * PROOFSIZE:
            prev[n] = head[bits]

    n_edges = 0
    i = 0   # start at uvs[0]

    while True:
        j = i
        k = j

        # Look for duplicate node in the reverse chain (branch check)
        while True:
            k = prev[k]
            if k == i:
                break
            if uvs[k] == uvs[i]:
                if j != i:
                    return EPoWStatus.POW_BRANCH
                j = k

        if j == i:
            return EPoWStatus.POW_DEAD_END

        # Jump to the other endpoint of the same edge
        i = j ^ 1
        n_edges += 1

        if i == 0:
            break

    if n_edges == PROOFSIZE:
        return EPoWStatus.POW_OK
    else:
        return EPoWStatus.POW_SHORT_CYCLE

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
    if len(proof_nonces) < PROOFSIZE:
        return False, EPoWStatus.POW_TOO_SMALL
    if len(proof_nonces) > PROOFSIZE:
        return False, EPoWStatus.POW_TOO_BIG

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckarooz(proof_nonces, keys)

    if result == EPoWStatus.POW_OK:
        return True, result
    return False, result