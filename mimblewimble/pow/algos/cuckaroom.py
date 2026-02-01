from mimblewimble.pow.common import siphash_block, SipHashKeys
from mimblewimble.pow.common import PROOFSIZE, EDGE_MASK, NODE_MASK
from mimblewimble.pow.common import EPoWStatus

from typing import List

def verify_cuckaroom(proof: List[int], sip_keys: SipHashKeys) -> int:
    xor_all = 0
    fr = [0] * PROOFSIZE   # from nodes
    to = [0] * PROOFSIZE   # to nodes

    # 1. Basic checks + extract oriented edges
    for i in range(PROOFSIZE):
        nonce = proof[i]

        if nonce > EDGE_MASK:
            return EPoWStatus.POW_TOO_BIG

        if i > 0 and nonce <= proof[i-1]:
            return EPoWStatus.POW_TOO_BIG

        edge = siphash_block(sip_keys, nonce, 21, xor_all=True)
        u = edge & NODE_MASK
        v = (edge >> 32) & NODE_MASK

        fr[i] = u
        to[i] = v
        xor_all ^= u ^ v

    if xor_all != 0:
        return EPoWStatus.POW_NON_MATCHING

    # 2. Cycle detection (Grin-style reverse walk)
    MASK = 63

    head = [PROOFSIZE] * (MASK + 1)
    prev = [0] * PROOFSIZE
    visited = [False] * PROOFSIZE

    # Build reverse index (from-nodes)
    for i in range(PROOFSIZE):
        bits = fr[i] & MASK
        prev[i] = head[bits]
        head[bits] = i

    steps = 0
    current = 0

    while True:
        if visited[current]:
            return EPoWStatus.POW_BRANCH

        visited[current] = True
        target = to[current]
        bits = target & MASK
        k = head[bits]
        found = False

        while k != PROOFSIZE:
            if fr[k] == target:
                current = k
                found = True
                break
            k = prev[k]

        if not found:
            return EPoWStatus.POW_DEAD_END

        steps += 1
        if current == 0:
            break

    if steps != PROOFSIZE:
        return EPoWStatus.POW_SHORT_CYCLE

    return EPoWStatus.POW_OK

def cuckaroom_validate(
    proof_nonces: List[int],          # list of 42 edge indices (nonces)
    pre_pow_hash: bytes               # 32-byte blake2b hash of pre-PoW header
) -> tuple[bool, str]:
    """
    Returns (True, "OK") or (False, error message)
    """
    if len(proof_nonces) < PROOFSIZE:
        return False, EPoWStatus.POW_TOO_SMALL
    if len(proof_nonces) > PROOFSIZE:
        return False, EPoWStatus.POW_TOO_BIG

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckaroom(proof_nonces, keys)

    if result == EPoWStatus.POW_OK:
        return True, result
    return False, result