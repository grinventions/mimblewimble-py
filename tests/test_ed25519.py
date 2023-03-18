import os

from nacl import bindings

from mimblewimble.keychain import KeyChain

def test_nacl():
    seed = os.urandom(32)
    pk, sk = bindings.crypto_sign_seed_keypair(seed)

    message = os.urandom(128)
    signature = bindings.crypto_sign(message, sk)

    msg = bindings.crypto_sign_open(signature, pk)
    assert msg == message


def test_signature():
    master_seed = os.urandom(32)
    path = 'm/0/1/0'

    keychain = KeyChain.fromSeed(master_seed)

    message = os.urandom(128)
    signature = keychain.signED25519(message, path)
    address = keychain.deriveSlatepackAddress(path)

    valid = KeyChain.verifyED25519(address, signature, message)
    assert valid
