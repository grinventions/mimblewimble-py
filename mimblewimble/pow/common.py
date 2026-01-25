import struct
from typing import Tuple, List

# --------------------------------------------------------------------
#  Configuration constants
# --------------------------------------------------------------------
PROOFSIZE = 42

EDGE_BLOCK_BITS = 6
EDGE_BLOCK_SIZE = 1 << EDGE_BLOCK_BITS
EDGE_BLOCK_MASK = EDGE_BLOCK_SIZE - 1

# You can override this if needed (used in final rotation step)
ROTE = 21


class SipHashKeys:
    """Container for 4×64-bit SipHash keys"""
    def __init__(self, keybuf: bytes):
        # Expect exactly 32 bytes
        assert len(keybuf) >= 32, "keybuf must be at least 32 bytes"
        # Little-endian 64-bit integers
        unpacked = struct.unpack_from("<4Q", keybuf, 0)
        self.k0, self.k1, self.k2, self.k3 = unpacked


class SipHashState:
    """Mutable SipHash state (v0,v1,v2,v3)"""
    def __init__(self, keys: SipHashKeys):
        self.v0 = keys.k0
        self.v1 = keys.k1
        self.v2 = keys.k2
        self.v3 = keys.k3

    def xor_lanes(self) -> int:
        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3

    def xor_with(self, other: 'SipHashState') -> None:
        self.v0 ^= other.v0
        self.v1 ^= other.v1
        self.v2 ^= other.v2
        self.v3 ^= other.v3

    @staticmethod
    def rotl(x: int, b: int) -> int:
        """Rotate left 64-bit value"""
        return ((x << b) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - b))

    def sip_round(self) -> None:
        self.v0 = (self.v0 + self.v1) & 0xFFFFFFFFFFFFFFFF
        self.v2 = (self.v2 + self.v3) & 0xFFFFFFFFFFFFFFFF

        self.v1 = self.rotl(self.v1, 13)
        self.v3 = self.rotl(self.v3, 16)

        self.v1 ^= self.v0
        self.v3 ^= self.v2

        self.v0 = self.rotl(self.v0, 32)
        self.v2 = (self.v2 + self.v1) & 0xFFFFFFFFFFFFFFFF
        self.v0 = (self.v0 + self.v3) & 0xFFFFFFFFFFFFFFFF

        self.v1 = self.rotl(self.v1, 17)
        self.v3 = self.rotl(self.v3, ROTE)

        self.v1 ^= self.v2
        self.v3 ^= self.v0

        self.v2 = self.rotl(self.v2, 32)

    def hash24(self, nonce: int) -> None:
        self.v3 ^= nonce
        self.sip_round()
        self.sip_round()

        self.v0 ^= nonce
        self.v2 ^= 0xFF

        self.sip_round()
        self.sip_round()
        self.sip_round()
        self.sip_round()


def sipblock(
    keys: SipHashKeys,
    edge: int,
    rotE: int = ROTE
) -> Tuple[int, List[int]]:
    """
    Compute EDGE_BLOCK_SIZE SipHash outputs for the block containing `edge`.
    Returns (siphash_value_for_edge, block_buffer)
    """
    shs = SipHashState(keys)

    edge0 = edge & ~EDGE_BLOCK_MASK   # round down to block start

    buf = [0] * EDGE_BLOCK_SIZE

    for i in range(EDGE_BLOCK_SIZE):
        shs.hash24(edge0 + i)
        buf[i] = shs.xor_lanes()

    # The last value is XORed into all previous ones (Cuckaroo trick)
    last = buf[EDGE_BLOCK_MASK]
    for i in range(EDGE_BLOCK_MASK):
        buf[i] ^= last

    edge_index_in_block = edge & EDGE_BLOCK_MASK
    return buf[edge_index_in_block], buf