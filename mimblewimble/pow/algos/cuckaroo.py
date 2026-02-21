from typing import List
from mimblewimble.pow.common import siphash_block, SipHashKeys

from mimblewimble.pow.common import PROOFSIZE
from mimblewimble.pow.common import EPoWStatus


def verify_cuckaroo(proof: list[int], keys: SipHashKeys, edge_bits: int) -> int:
    edge_mask = (1 << edge_bits) - 1
    node_mask = edge_mask  # Cuckaroo29: nodes & edges same size

    uvs: List[int] = [0] * (2 * PROOFSIZE)
    xor0 = 0
    xor1 = 0

    # Step 1: extract edges + endpoints + XOR check
    for n in range(PROOFSIZE):
        edge_idx = proof[n]

        if edge_idx > edge_mask:
            return EPoWStatus.POW_TOO_BIG

        if n > 0 and edge_idx <= proof[n - 1]:
            return EPoWStatus.POW_TOO_SMALL

        edge = siphash_block(keys, edge_idx)
        u = edge & node_mask
        v = (edge >> 32) & node_mask

        uvs[2 * n] = u
        uvs[2 * n + 1] = v

        xor0 ^= u
        xor1 ^= v

    if xor0 != 0 or xor1 != 0:
        return EPoWStatus.POW_NON_MATCHING

    # Step 2: cycle walk (Grin style)
    mask = (1 << (PROOFSIZE - 1).bit_length()) - 1

    head_u = [2 * PROOFSIZE] * (mask + 1)
    head_v = [2 * PROOFSIZE] * (mask + 1)
    prev = [0] * (2 * PROOFSIZE)

    for n in range(PROOFSIZE):
        ubits = uvs[2 * n] & mask
        prev[2 * n] = head_u[ubits]
        head_u[ubits] = 2 * n

        vbits = uvs[2 * n + 1] & mask
        prev[2 * n + 1] = head_v[vbits]
        head_v[vbits] = 2 * n + 1

    # close cycles
    for n in range(PROOFSIZE):
        ui = 2 * n
        if prev[ui] == 2 * PROOFSIZE:
            prev[ui] = head_u[uvs[ui] & mask]
        vi = 2 * n + 1
        if prev[vi] == 2 * PROOFSIZE:
            prev[vi] = head_v[uvs[vi] & mask]

    # walk
    steps = 0
    i = 0
    while True:
        j = i
        k = j
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

        i = j ^ 1
        steps += 1

        if i == 0:
            break

    if steps != PROOFSIZE:
        return EPoWStatus.POW_SHORT_CYCLE

    return EPoWStatus.POW_OK


def cuckaroo_validate(
    proof_nonces: list[int],  # list of 42 edge indices
    pre_pow_hash: bytes,  # 32 bytes usually (blake2b result)
    edge_bits: int,
) -> bool:

    if len(proof_nonces) < PROOFSIZE:
        return False, EPoWStatus.POW_TOO_SMALL
    if len(proof_nonces) > PROOFSIZE:
        return False, EPoWStatus.POW_TOO_BIG

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckaroo(proof_nonces, keys, edge_bits)

    if result == EPoWStatus.POW_OK:
        return True, result
    return False, result
