from typing import List

from mimblewimble.pow.common import SipHashKeys, PROOFSIZE
from mimblewimble.pow.common import EPoWStatus

ROTE = 21

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
    num_edges  = 1 << edge_bits
    edge_mask  = num_edges - 1

    xor0 = xor1 = (PROOFSIZE // 2) & 1   # parity initialization
    endpoints = [0] * (2 * PROOFSIZE)    # u0,v0, u1,v1, ...

    # Phase 1: extract endpoints + xor check
    for i in range(PROOFSIZE):
        edge = edges[i]

        if edge > edge_mask:
            return EPoWStatus.POW_TOO_BIG

        if i > 0 and edge <= edges[i - 1]:
            return EPoWStatus.POW_TOO_SMALL

        u = sipnode(keys, edge, 0, edge_mask)
        v = sipnode(keys, edge, 1, edge_mask)

        endpoints[2 * i]     = u
        endpoints[2 * i + 1] = v

        xor0 ^= u
        xor1 ^= v

    if xor0 | xor1:
        return EPoWStatus.POW_NON_MATCHING

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
                    return EPoWStatus.POW_BRANCH
                j = k
            k = (k + 2) % (2 * PROOFSIZE)

        if j is None or endpoints[j] == endpoints[i]:
            return EPoWStatus.POW_DEAD_END

        next_i = j ^ 1
        n += 1

        if next_i == 0:
            break

        i = next_i

    return EPoWStatus.POW_OK if n == PROOFSIZE else EPoWStatus.POW_SHORT_CYCLE

def cuckatoo_validate(
    proof_nonces: List[int],
    pre_pow_hash: bytes, # blake2b(pre-pow-header)
    edge_bits: int       # usually 29, 31, sometimes variable
) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, message: str)
    """
    if len(proof_nonces) < PROOFSIZE:
        return False, EPoWStatus.POW_TOO_SMALL
    if len(proof_nonces) > PROOFSIZE:
        return False, EPoWStatus.POW_TOO_BIG

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckatoo(proof_nonces, keys, edge_bits)

    if result == EPoWStatus.POW_OK:
        return True, result
    return False, result