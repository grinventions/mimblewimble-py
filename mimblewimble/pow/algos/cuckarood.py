from typing import List
from mimblewimble.pow.common import sipblock, SipHashKeys

EDGEBITS = 29

NEDGES    = 1 << EDGEBITS
NNODES    = 1 << (EDGEBITS - 1)
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1

SIPHASH_BLOCK_BITS = 6
SIPHASH_BLOCK_SIZE = 1 << SIPHASH_BLOCK_BITS
SIPHASH_BLOCK_MASK = SIPHASH_BLOCK_SIZE - 1

PROOFSIZE = 42                    # most common value in Cuckatoo/Cuckarood
POW_OK = 0
POW_TOO_BIG = 1
POW_TOO_SMALL = 2
POW_UNBALANCED = 3
POW_NON_MATCHING = 4
POW_BRANCH = 5
POW_DEAD_END = 6
POW_SHORT_CYCLE = 7

errstr = {
    POW_OK: "POW_OK",
    POW_TOO_BIG: "edge too big",
    POW_TOO_SMALL: "edges not ascending",
    POW_UNBALANCED: "unbalanced partition",
    POW_NON_MATCHING: "xor endpoints != 0",
    POW_BRANCH: "branch detected",
    POW_DEAD_END: "dead end (no reverse edge)",
    POW_SHORT_CYCLE: "cycle shorter than proof size"
}


MASK_64 = 0xFFFFFFFFFFFFFFFF

def rotl(x: int, r: int) -> int:
    x = x & MASK_64
    return ((x << r) & MASK_64) | (x >> (64 - r))

class SipHashRot:
    def __init__(self, k: list[int]):
        self.v0 = k[0] & MASK_64
        self.v1 = k[1] & MASK_64
        self.v2 = k[2] & MASK_64
        self.v3 = k[3] & MASK_64

    def round(self, rot_last: int):
        self.v0 = (self.v0 + self.v1) & MASK_64
        self.v2 = (self.v2 + self.v3) & MASK_64
        self.v1 = rotl(self.v1, 13)
        self.v3 = rotl(self.v3, 16)
        self.v1 ^= self.v0
        self.v3 ^= self.v2
        self.v0 = rotl(self.v0, 32)

        self.v2 = (self.v2 + self.v1) & MASK_64
        self.v0 = (self.v0 + self.v3) & MASK_64
        self.v1 = rotl(self.v1, 17)
        self.v3 = rotl(self.v3, rot_last)
        self.v1 ^= self.v2
        self.v3 ^= self.v0
        self.v2 = rotl(self.v2, 32)

    def hash(self, nonce: int, rot_e: int):
        self.v3 ^= nonce & MASK_64
        self.round(rot_e)
        self.round(rot_e)
        self.v0 ^= nonce & MASK_64
        self.v2 ^= 0xFF
        for _ in range(4):
            self.round(rot_e)

    def digest(self) -> int:
        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3   # already masked


def sipblock(keys: List[int], edge_idx: int, rot_e: int = 25) -> int:
    nonce0 = edge_idx & ~SIPHASH_BLOCK_MASK
    nonce_i = edge_idx & SIPHASH_BLOCK_MASK

    nonce_hash = [0] * SIPHASH_BLOCK_SIZE
    hasher = SipHashRot(keys)

    for i in range(SIPHASH_BLOCK_SIZE):
        hasher.hash(nonce0 + i, rot_e)
        nonce_hash[i] = hasher.digest()

    # Selective XOR – matches the original logic
    xor_val = nonce_hash[nonce_i]
    if False or nonce_i == SIPHASH_BLOCK_MASK:   # xor_all = False here
        xor_start = nonce_i + 1
    else:
        xor_start = SIPHASH_BLOCK_MASK          # most common case

    for i in range(xor_start, SIPHASH_BLOCK_SIZE):
        xor_val ^= nonce_hash[i]

    return xor_val

def verify_cuckarood(edges: list[int], keys) -> int:
    sip_keys = [keys.k0, keys.k1, keys.k2, keys.k3]

    uvs = [0] * (2 * PROOFSIZE)
    xor_u = 0
    xor_v = 0
    ndir = [0, 0]

    # 1. Extract endpoints + basic checks
    for i in range(PROOFSIZE):
        edge_idx = edges[i]
        direction = edge_idx & 1

        if edge_idx >= EDGE_MASK:
            return POW_TOO_BIG

        if i > 0 and edge_idx <= edges[i-1]:
            return POW_TOO_SMALL

        if ndir[direction] >= PROOFSIZE // 2:
            return POW_UNBALANCED

        hash_val = sipblock(sip_keys, edge_idx, 25)

        u = hash_val & NODE_MASK
        v = (hash_val >> 32) & NODE_MASK

        idx = 4 * ndir[direction] + 2 * direction
        uvs[idx]     = u
        uvs[idx + 1] = v

        xor_u ^= u
        xor_v ^= v

        ndir[direction] += 1

    if xor_u != 0 or xor_v != 0:
        return POW_NON_MATCHING

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
                    return POW_BRANCH
                j = k
            k = prev[k]

        if j == i:
            return POW_DEAD_END

        i = j ^ 1
        steps += 1

        if i == 0:
            break
        if steps > PROOFSIZE * 2:
            return POW_DEAD_END

    if steps != PROOFSIZE:
        return POW_SHORT_CYCLE

    return POW_OK

def cuckarood_validate(proof_nonces: list[int], pre_pow_hash: bytes) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, error_message: str)
    """
    if len(proof_nonces) != PROOFSIZE:
        return False, f"Invalid proof size (expected {PROOFSIZE}, got {len(proof_nonces)})"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckarood(proof_nonces, keys)

    if result == POW_OK:
        return True, "Valid"
    else:
        return False, errstr.get(result, f"Unknown error code {result}")