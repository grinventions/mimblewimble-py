import os
import pytest

from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY
from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy
from secp256k1_zkp_mw import secp256k1_pedersen_blind_sum

from mimblewimble.models.transaction import BlindingFactor

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.public_key import PublicKey
from mimblewimble.crypto.pedersen import Pedersen

# test adding blinded commitment with transparent one
def test_adding_blinded_commitments_with_transparent():
    p = Pedersen()

    blinding_factor = BlindingFactor(os.urandom(32))
    blinded_commitment = p.commit(2, blinding_factor)

    transparent_factor = BlindingFactor(bytes([0x00 for j in range(32)]))
    transparent_commitment = p.commit(3, transparent_factor)

    summed = p.commitSum([blinded_commitment, transparent_commitment], [])
    another_blinded_commitment = p.commit(5, blinding_factor)

    # they will match because of same blinding factor
    assert summed == another_blinded_commitment

# test adding 2 blinded commitment
def test_adding_two_blinded_commitment():
    p = Pedersen()

    blinding_factor_a = BlindingFactor(os.urandom(32))
    blinded_commitment_a = p.commit(2, blinding_factor_a)

    blinding_factor_b = BlindingFactor(os.urandom(32))
    blinded_commitment_b = p.commit(3, blinding_factor_b)

    summed = p.commitSum([blinded_commitment_a, blinded_commitment_b], [])

    blinding_factor_c = p.blindSum([blinding_factor_a, blinding_factor_b], [])
    blinded_commitment_c = p.commit(5, blinding_factor_c)

    # they will match because blinding factor of c is the sum
    # of blinding factors of a and b
    assert summed == blinded_commitment_c

# test adding negative blinded commitment
def test_adding_negative_blinded_commitment():
    p = Pedersen()

    blinding_factor_a = BlindingFactor(os.urandom(32))
    blinded_commitment_a = p.commit(3, blinding_factor_a)

    blinding_factor_b = BlindingFactor(os.urandom(32))
    blinded_commitment_b = p.commit(2, blinding_factor_b)

    difference = p.commitSum([blinded_commitment_a], [blinded_commitment_b])

    blinding_factor_c = p.blindSum([blinding_factor_a], [blinding_factor_b])
    blinded_commitment_c = p.commit(1, blinding_factor_c)

    # they will match because blinding factor of c is the difference
    # of blinding factors of a and b
    assert difference == blinded_commitment_c

# test public key to commitment
def test_public_key_to_commitment():
    p = Pedersen()
    public_key = PublicKey.fromHex(
        '02f434a6b929d0aa6ac757bbe387075066d51ee5308d5be91d2fb478a494d38bdf')

    commitment = p.toCommitment(public_key)
    commitment_bytes = commitment.getBytes()

    # commitment = Commitment.fromPublicKey(public_key)
    expected_commitment = Commitment.fromHex(
        '08f434a6b929d0aa6ac757bbe387075066d51ee5308d5be91d2fb478a494d38bdf')
    assert commitment == expected_commitment
