from enum import IntEnum

import struct
from typing import Tuple, List

# constants (adjust if needed in your project)
PROOFSIZE = 42          # most common for Cuckaroo29 etc.
EDGE_BLOCK_SIZE = 64    # usually 64 for sipblock implementation

EDGEBITS = 29
NEDGES = 1 << EDGEBITS
NNODES = 1 << (EDGEBITS - 1)
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1

SIPHASH_BLOCK_BITS = 6
SIPHASH_BLOCK_SIZE = 1 << SIPHASH_BLOCK_BITS
SIPHASH_BLOCK_MASK = SIPHASH_BLOCK_SIZE - 1

class EPoWStatus(IntEnum):
    POW_OK = 0
    POW_TOO_BIG = 1
    POW_TOO_SMALL = 2
    POW_NON_MATCHING = 3
    POW_BRANCH = 4
    POW_DEAD_END = 5
    POW_SHORT_CYCLE = 6
    POW_UNBALANCED = 7

MASK64 = (1 << 64) - 1

def rol64(x: int, k: int) -> int:
    x &= MASK64
    return ((x << k) & MASK64) | (x >> (64 - k))

class SipHashKeys:
    """Container for 4×64-bit SipHash keys"""
    def __init__(self, keybuf: bytes):
        # Expect exactly 32 bytes
        assert len(keybuf) >= 32, "keybuf must be at least 32 bytes"
        # Little-endian 64-bit integers
        unpacked = struct.unpack_from("<4Q", keybuf, 0)
        self.k0, self.k1, self.k2, self.k3 = unpacked

class SipHash24:
    def __init__(self, keys: SipHashKeys):
        self.v0 = keys.k0 & MASK64
        self.v1 = keys.k1 & MASK64
        self.v2 = keys.k2 & MASK64
        self.v3 = keys.k3 & MASK64

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
    keys: SipHashKeys,
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