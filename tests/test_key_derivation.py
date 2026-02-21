import pytest

from mimblewimble.keychain import KeyChain


def test_key_derivation():
    master_seed = bytes.fromhex(
        "b873212f885ccffbf4692afcb84bc2e55886de2dfa07d90f5c3c239abc31c0a6ce047e30fd8bf6a281e71389aa82d73df74c7bbfb3b06b4639a5cee775cccd3c"
    )
    path = "m/1/2/3/4"
    kc = KeyChain.fromSeed(master_seed)
    key1234 = kc.derivePrivateKeyAmount(path, 1234)


@pytest.mark.skip(reason="no way of currently testing this")
def test_age_encryption():
    master_seed = "2d638479b8e9ae00bee803faa7d40a8911d410bbb760d6c7da3ef52ce284cca8"
    kc = KeyChain.fromSeed(bytes.fromhex(master_seed))
    path = "m/0/1/0"
    plaintext = bytes.fromhex(
        "a82206e04a2e6a6c1734da52cf25695a5cac94502303dfc5eef21872801b4aff020450d285106f342cae832a0307"
    )
    fingerprint, derived_secret, ciphertext = kc.ageEncrypt(plaintext, path)

    # without fingerprint
    decrypted = kc.ageDecrypt(ciphertext, path, derived_secret)
    assert plaintext == decrypted

    # with fingerprint
    decrypted = kc.ageDecrypt(ciphertext, path, derived_secret, fingerprint=fingerprint)
    assert plaintext == decrypted
