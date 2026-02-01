from typing import List

from mimblewimble.pow.common import SipHashKeys, SipHashState

# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

PROOFSIZE = 42
EDGEBITS  = 29
NEDGES    = 1 << EDGEBITS
NNODES    = 1 << EDGEBITS           # ← Cuckarooz: monopartite
EDGE_MASK = NEDGES - 1
NODE_MASK = NNODES - 1
SIPHASH_BLOCK_BITS = 6
SIPHASH_BLOCK_SIZE = 1 << SIPHASH_BLOCK_BITS
SIPHASH_BLOCK_MASK = SIPHASH_BLOCK_SIZE - 1

# ────────────────────────────────────────────────
# Error codes
# ────────────────────────────────────────────────

POW_OK          = 0
POW_TOO_BIG     = 1
POW_NOT_ASCENDING = 2
POW_NON_MATCHING  = 3
POW_BRANCH      = 4
POW_DEAD_END    = 5
POW_SHORT_CYCLE = 6

POW_ERROR_MESSAGES = {
    POW_OK:            "POW_OK – valid proof",
    POW_TOO_BIG:       "edge nonce > EDGEMASK",
    POW_NOT_ASCENDING: "edge nonces not strictly increasing",
    POW_NON_MATCHING:  "XOR of all endpoints != 0 (endpoints do not pair up)",
    POW_BRANCH:        "branch detected (multiple matches for same endpoint)",
    POW_DEAD_END:      "dead end – no matching endpoint found",
    POW_SHORT_CYCLE:   "cycle shorter than PROOFSIZE (not a 42-cycle)",
}

MASK_64 = 0xFFFFFFFFFFFFFFFF

# ────────────────────────────────────────────────
# Helper functions
# ────────────────────────────────────────────────

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
    # Cuckarooz style: xor from nonce_i to end (full block xor)
    xor_val = nonce_hash[nonce_i]
    for i in range(nonce_i + 1, SIPHASH_BLOCK_SIZE):
        xor_val ^= nonce_hash[i]
    return xor_val

def verify_cuckarooz(proof: List[int], keys: SipHashKeys) -> int:
    sip_keys = [keys.k0, keys.k1, keys.k2, keys.k3]
    uvs = [0] * (2 * PROOFSIZE)          # flattened: u0,v0, u1,v1, ...
    xor_all = 0

    # 1. Basic checks + extract endpoints
    for i in range(PROOFSIZE):
        nonce = proof[i]

        if nonce > EDGE_MASK:
            return POW_TOO_BIG

        if i > 0 and nonce <= proof[i-1]:
            return POW_NOT_ASCENDING

        edge = sipblock(sip_keys, nonce, 21)
        u = edge & NODE_MASK
        v = (edge >> 32) & NODE_MASK

        uvs[2 * i]     = u
        uvs[2 * i + 1] = v
        xor_all ^= u ^ v

    if xor_all != 0:
        return POW_NON_MATCHING

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
                    return POW_BRANCH
                j = k

        if j == i:
            return POW_DEAD_END

        # Jump to the other endpoint of the same edge
        i = j ^ 1
        n_edges += 1

        if i == 0:
            break

    if n_edges == PROOFSIZE:
        return POW_OK
    else:
        return POW_SHORT_CYCLE

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

    if len(proof_nonces) != PROOFSIZE:
        return False, f"Invalid proof size (expected {PROOFSIZE}, got {len(proof_nonces)})"

    keys = SipHashKeys(pre_pow_hash)
    result = verify_cuckarooz(proof_nonces, keys)

    if result == POW_OK:
        return True, "POW_OK"

    msg = POW_ERROR_MESSAGES.get(result, f"Unknown error code {result}")
    return False, msg