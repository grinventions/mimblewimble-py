import os
import pytest

from mimblewimble.keychain import KeyChain

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.bulletproof import EBulletproofType
from mimblewimble.crypto.pedersen import Pedersen

from mimblewimble.models.transaction import BlindingFactor


def test_rewind_bulletproof_original():
    master_seed = os.urandom(32)

    bulletproof_type = EBulletproofType.ORIGINAL

    path = 'm/0/1/0'
    amount = 45
    keychain = KeyChain.fromSeed(master_seed)
    blinding_factor = keychain.derivePrivateKeyAmount(
        path, amount)

    p = Pedersen()
    commitment = p.commit(amount, blinding_factor)
    del p

    rangeproof = keychain.generateRangeProof(
        path, amount, commitment,
        blinding_factor, bulletproof_type)

    rewoundproof = keychain.rewindRangeProof(
        commitment, rangeproof, bulletproof_type)

    assert amount == rewoundproof.getAmount()
    assert blinding_factor.getBytes() == rewoundproof.getBlindingFactor().getBytes()
    assert KeyChain.getKeyIndices(path) == rewoundproof.toKeyIndices(bulletproof_type)

def test_rewind_bulletproof_enhanced():
    master_seed = os.urandom(32)

    bulletproof_type = EBulletproofType.ENHANCED

    path = 'm/0/1/0'
    amount = 45
    keychain = KeyChain.fromSeed(master_seed)
    blinding_factor = keychain.derivePrivateKeyAmount(
        path, amount)

    p = Pedersen()
    commitment = p.commit(amount, blinding_factor)
    del p

    rangeproof = keychain.generateRangeProof(
        path, amount, commitment,
        blinding_factor, bulletproof_type)

    rewoundproof = keychain.rewindRangeProof(
        commitment, rangeproof, bulletproof_type)

    assert amount == rewoundproof.getAmount()
    assert KeyChain.getKeyIndices(path) == rewoundproof.toKeyIndices(bulletproof_type)
