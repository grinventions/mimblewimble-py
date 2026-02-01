from typing import List
from mimblewimble.pow.common import siphash_block, SipHashKeys

from mimblewimble.pow.common import PROOFSIZE, EPoWStatus

EDGEBITS = 29

NEDGES    = 1 << EDGEBITS
NNODES    = 1 << (EDGEBITS - 1)
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1

errstr = {
    EPoWStatus.POW_OK: "POW_OK",
    EPoWStatus.POW_TOO_BIG: "edge too big",
    EPoWStatus.POW_TOO_SMALL: "edges not ascending",
    EPoWStatus.POW_UNBALANCED: "unbalanced partition",
    EPoWStatus.POW_NON_MATCHING: "xor endpoints != 0",
    EPoWStatus.POW_BRANCH: "branch detected",
    EPoWStatus.POW_DEAD_END: "dead end (no reverse edge)",
    EPoWStatus.POW_SHORT_CYCLE: "cycle shorter than proof size"
}

def verify_cuckarood(edges: list[int], sip_keys) -> int:
    uvs = [0] * (2 * PROOFSIZE)
    xor_u = 0
    xor_v = 0
    ndir = [0, 0]

    # 1. Extract endpoints + basic checks
    for i in range(PROOFSIZE):
        edge_idx = edges[i]
        direction = edge_idx & 1

        if edge_idx >= EDGE_MASK:
            return EPoWStatus.POW_TOO_BIG

        if i > 0 and edge_idx <= edges[i-1]:
            return EPoWStatus.POW_TOO_SMALL

        if ndir[direction] >= PROOFSIZE // 2:
            return EPoWStatus.POW_UNBALANCED

        hash_val = siphash_block(sip_keys, edge_idx, 25)

        u = hash_val & NODE_MASK
        v = (hash_val >> 32) & NODE_MASK

        idx = 4 * ndir[direction] + 2 * direction
        uvs[idx]     = u
        uvs[idx + 1] = v

        xor_u ^= u
        xor_v ^= v

        ndir[direction] += 1

    if xor_u != 0 or xor_v != 0:
        return EPoWStatus.POW_NON_MATCHING

    NIL = 2 * PROOFSIZE
    MASK = 63               # 2^6 - 1 — good enough for 42 proofs

    headu = [NIL] * (MASK + 1)
    headv = [NIL] * (MASK + 1)
    prev  = [0]   * (2 * PROOFSIZE)

    ndir = [0, 0]

    # Build reverse multimap (linked lists)
    for edge_idx in range(PROOFSIZE):
        dir_ = edges[edge_idx] & 1
        idx = 4 * ndir[dir_] + 2 * dir_
        u = uvs[idx]
        v = uvs[idx + 1]

        # u entry
        ubits = ((u << 1) | dir_) & MASK
        prev[idx] = headu[ubits]
        headu[ubits] = idx

        # v entry
        vbits = ((v << 1) | dir_) & MASK
        prev[idx + 1] = headv[vbits]
        headv[vbits] = idx + 1

        ndir[dir_] += 1

    # ─── Walk the cycle ───────────────────────────────────────
    steps = 0
    i = 0

    while True:
        j = i
        heads = headv if (i & 1) else headu
        opposite_dir = 1 - (i & 1)
        key = ((uvs[i] << 1) | opposite_dir) & MASK

        k = heads[key]
        while k != NIL:
            if uvs[k] == uvs[i]:
                if j != i:
                    return EPoWStatus.POW_BRANCH
                j = k
            k = prev[k]

        if j == i:
            return EPoWStatus.POW_DEAD_END

        i = j ^ 1
        steps += 1

        if i == 0:
            break
        if steps > PROOFSIZE * 2:
            return EPoWStatus.POW_DEAD_END

    if steps != PROOFSIZE:
        return EPoWStatus.POW_SHORT_CYCLE

    return EPoWStatus.POW_OK

def cuckarood_validate(proof_nonces: list[int], pre_pow_hash: bytes) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, error_message: str)
    """
    if len(proof_nonces) < PROOFSIZE:
        return False, EPoWStatus.POW_TOO_SMALL
    if len(proof_nonces) > PROOFSIZE:
        return False, EPoWStatus.POW_TOO_BIG

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckarood(proof_nonces, keys)

    if result == EPoWStatus.POW_OK:
        return True, result
    return False, result