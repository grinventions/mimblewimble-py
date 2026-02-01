from mimblewimble.pow.common import SipHashKeys

from typing import List

PROOFSIZE = 42
EDGEBITS = 29
NEDGES = 1 << EDGEBITS
NNODES = 1 << (EDGEBITS - 1)
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1

SIPHASH_BLOCK_BITS = 6
SIPHASH_BLOCK_SIZE = 1 << SIPHASH_BLOCK_BITS
SIPHASH_BLOCK_MASK = SIPHASH_BLOCK_SIZE - 1

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


MASK_64 = 0xFFFFFFFFFFFFFFFF

def rotl(x: int, r: int) -> int:
    x = x & MASK_64
    return ((x << r) & MASK_64) | (x >> (64 - r))


class SipHashRot:
    def __init__(self, k: List[int]):
        self.v0 = k[0]
        self.v1 = k[1]
        self.v2 = k[2]
        self.v3 = k[3]

    def round(self, rot_last: int):
        self.v0 += self.v1
        self.v2 += self.v3
        self.v1 = rotl(self.v1, 13)
        self.v3 = rotl(self.v3, 16)
        self.v1 ^= self.v0
        self.v3 ^= self.v2
        self.v0 = rotl(self.v0, 32)

        self.v2 += self.v1
        self.v0 += self.v3
        self.v1 = rotl(self.v1, 17)
        self.v3 = rotl(self.v3, rot_last)
        self.v1 ^= self.v2
        self.v3 ^= self.v0
        self.v2 = rotl(self.v2, 32)

    def hash(self, nonce: int, rot_e: int):
        self.v3 ^= nonce
        self.round(rot_e)
        self.round(rot_e)
        self.v0 ^= nonce
        self.v2 ^= 0xFF
        for _ in range(4):
            self.round(rot_e)

    def digest(self) -> int:
        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3


def sipblock(keys: List[int], edge_idx: int, rot_e: int = 21) -> int:
    nonce0 = edge_idx & ~SIPHASH_BLOCK_MASK
    nonce_i = edge_idx & SIPHASH_BLOCK_MASK

    nonce_hash = [0] * SIPHASH_BLOCK_SIZE
    hasher = SipHashRot(keys)

    for i in range(SIPHASH_BLOCK_SIZE):
        hasher.hash(nonce0 + i, rot_e)
        nonce_hash[i] = hasher.digest()

    # Cuckaroom → full XOR from nonce_i onwards
    xor_val = nonce_hash[nonce_i]
    for i in range(nonce_i + 1, SIPHASH_BLOCK_SIZE):
        xor_val ^= nonce_hash[i]

    return xor_val

def verify_cuckaroom(proof: List[int], keys: SipHashKeys) -> int:
    sip_keys = [keys.k0, keys.k1, keys.k2, keys.k3]
    xor_all = 0
    fr = [0] * PROOFSIZE   # from nodes
    to = [0] * PROOFSIZE   # to nodes

    # 1. Basic checks + extract oriented edges
    for i in range(PROOFSIZE):
        nonce = proof[i]

        if nonce > EDGE_MASK:
            return POW_TOO_BIG

        if i > 0 and nonce <= proof[i-1]:
            return POW_TOO_BIG

        edge = sipblock(sip_keys, nonce, 21)
        u = edge & NODE_MASK
        v = (edge >> 32) & NODE_MASK

        fr[i] = u
        to[i] = v
        xor_all ^= u ^ v

    if xor_all != 0:
        return POW_NON_MATCHING

    # 2. Cycle detection (Grin-style reverse walk)
    MASK = 63          # 2⁶-1 — good enough for 42 edges
    # MASK = 127       # 2⁷-1 — alternative

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
            return POW_BRANCH

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
            return POW_DEAD_END

        steps += 1
        if current == 0:
            break

    if steps != PROOFSIZE:
        return POW_SHORT_CYCLE

    return POW_OK

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