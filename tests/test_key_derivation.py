from mimblewimble.keychain import KeyChain


def test_key_derivation():
    master_seed = bytes.fromhex('b873212f885ccffbf4692afcb84bc2e55886de2dfa07d90f5c3c239abc31c0a6ce047e30fd8bf6a281e71389aa82d73df74c7bbfb3b06b4639a5cee775cccd3c')
    path = 'm/1/2/3/4'
    kc = KeyChain.fromSeed(master_seed)
    key1234 = kc.derivePrivateKeyAmount(path, 1234)
