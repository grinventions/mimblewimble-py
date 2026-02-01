from typing import List
from mimblewimble.pow.common import sipblock, SipHashKeys


# constants (adjust if needed in your project)
PROOFSIZE = 42          # most common for Cuckaroo29 etc.
EDGE_BLOCK_SIZE = 64    # usually 64 for sipblock implementation

SIPHASH_BLOCK_BITS = 6
SIPHASH_BLOCK_SIZE = 1 << SIPHASH_BLOCK_BITS
SIPHASH_BLOCK_MASK = SIPHASH_BLOCK_SIZE - 1

POW_OK           = 0
POW_TOO_BIG      = 1
POW_TOO_SMALL    = 2
POW_NON_MATCHING = 3
POW_BRANCH       = 4
POW_DEAD_END     = 5
POW_SHORT_CYCLE  = 6

MASK64 = (1 << 64) - 1

def rol64(x: int, k: int) -> int:
    x &= MASK64
    return ((x << k) & MASK64) | (x >> (64 - k))

class SipHash24:
    def __init__(self, keys: List[int]):
        self.v0 = keys[0] & MASK64
        self.v1 = keys[1] & MASK64
        self.v2 = keys[2] & MASK64
        self.v3 = keys[3] & MASK64

    def round(self, rot_e: int):
        self.v0 = (self.v0 + self.v1) & MASK64
        self.v2 = (self.v2 + self.v3) & MASK64
        self.v1 = rol64(self.v1, 13)
        self.v3 = rol64(self.v3, 16)
        self.v1 ^= self.v0
        self.v3 ^= self.v2
        self.v0 = rol64(self.v0, 32)
        self.v2 = (self.v2 + self.v1) & MASK64
        self.v0 = (self.v0 + self.v3) & MASK64
        self.v1 = rol64(self.v1, 17)
        self.v3 = rol64(self.v3, rot_e)
        self.v1 ^= self.v2
        self.v3 ^= self.v0
        self.v2 = rol64(self.v2, 32)

    def hash(self, nonce: int, rot_e: int):
        self.v3 ^= nonce & MASK64
        self.round(rot_e)
        self.round(rot_e)
        self.v0 ^= nonce & MASK64
        self.v2 ^= 0xff
        for _ in range(4):
            self.round(rot_e)

    def digest(self) -> int:
        return (self.v0 ^ self.v1 ^ self.v2 ^ self.v3) & MASK64


def siphash24(keys: List[int], nonce: int) -> int:
    hasher = SipHash24(keys)
    hasher.hash(nonce, 21)
    return hasher.digest()

def siphash_block(
    keys: List[int],
    nonce: int,
    rot_e: int = 21,
    xor_all: bool = False
) -> int:
    nonce0 = nonce & ~SIPHASH_BLOCK_MASK
    nonce_i = nonce & SIPHASH_BLOCK_MASK

    nonce_hash = [0] * SIPHASH_BLOCK_SIZE
    hasher = SipHash24(keys)

    for i in range(SIPHASH_BLOCK_SIZE):
        hasher.hash(nonce0 + i, rot_e)
        nonce_hash[i] = hasher.digest()

    xor_val = nonce_hash[nonce_i]
    start = nonce_i + 1 if (xor_all or nonce_i == SIPHASH_BLOCK_MASK) else SIPHASH_BLOCK_MASK

    for i in range(start, SIPHASH_BLOCK_SIZE):
        xor_val ^= nonce_hash[i]

    return xor_val & MASK64

def verify_cuckaroo(proof: list[int], siphashkeys: SipHashKeys, edge_bits: int) -> int:
    keys = [siphashkeys.k0, siphashkeys.k1, siphashkeys.k2, siphashkeys.k3]
    edge_mask = (1 << edge_bits) - 1
    node_mask = edge_mask   # Cuckaroo29: nodes & edges same size

    uvs: List[int] = [0] * (2 * PROOFSIZE)
    xor0 = 0
    xor1 = 0

    # Step 1: extract edges + endpoints + XOR check
    for n in range(PROOFSIZE):
        edge_idx = proof[n]

        if edge_idx > edge_mask:
            return POW_TOO_BIG

        if n > 0 and edge_idx <= proof[n-1]:
            return POW_TOO_SMALL

        edge = siphash_block(keys, edge_idx)
        u = edge & node_mask
        v = (edge >> 32) & node_mask

        uvs[2*n]     = u
        uvs[2*n + 1] = v

        xor0 ^= u
        xor1 ^= v

    if xor0 != 0 or xor1 != 0:
        return POW_NON_MATCHING

    # Step 2: cycle walk (Grin style)
    mask = (1 << (PROOFSIZE-1).bit_length()) - 1

    head_u = [2 * PROOFSIZE] * (mask + 1)
    head_v = [2 * PROOFSIZE] * (mask + 1)
    prev   = [0] * (2 * PROOFSIZE)

    for n in range(PROOFSIZE):
        ubits = uvs[2*n]     & mask
        prev[2*n]     = head_u[ubits]
        head_u[ubits] = 2*n

        vbits = uvs[2*n + 1] & mask
        prev[2*n + 1] = head_v[vbits]
        head_v[vbits] = 2*n + 1

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
                    return POW_BRANCH
                j = k

        if j == i:
            return POW_DEAD_END

        i = j ^ 1
        steps += 1

        if i == 0:
            break

    if steps != PROOFSIZE:
        return POW_SHORT_CYCLE

    return POW_OK

def cuckaroo_validate(
    proof_nonces: list[int],    # list of 42 edge indices
    pre_pow_hash: bytes,        # 32 bytes usually (blake2b result)
    edge_bits: int
) -> bool:

    if len(proof_nonces) < PROOFSIZE:
        return False, "POW_TOO_SMALL"
    if len(proof_nonces) > PROOFSIZE:
        return False, "POW_TOO_BIG"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckaroo(proof_nonces, keys, edge_bits)

    if result != POW_OK:
        error_names = {
            POW_TOO_BIG:      "POW_TOO_BIG",
            POW_TOO_SMALL:    "POW_TOO_SMALL",
            POW_NON_MATCHING: "POW_NON_MATCHING",
            POW_BRANCH:       "POW_BRANCH",
            POW_DEAD_END:     "POW_DEAD_END",
            POW_SHORT_CYCLE:  "POW_SHORT_CYCLE",
        }
        err = error_names.get(result, f"unknown ({result})")
        return False, result

    return True, result