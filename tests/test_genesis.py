import hashlib
import unittest

from mimblewimble.genesis import floonet, mainnet


class GenesisTest(unittest.TestCase):
    def test_genesis(self):
        print('genesis test')
        genesis = mainnet
        assert genesis.getHash().hex() == '40adad0aec27797b48840aa9e00472015c21baea118ce7a2ff1a82c0f8f5bf82'
        #assert hashlib.blake2b(genesis.serialize()) == bytes.fromhex('6be6f34b657b785e558e85cc3b8bdb5bcbe8c10e7e58524c8027da7727e189ef')

    def test_floonet(self):
        print('floonet test')
        genesis = floonet
        assert genesis.getHash().hex() == 'edc758c1370d43e1d733f70f58cf187c3be8242830429b1676b89fd91ccf2dab'
        computed = hashlib.blake2b(genesis.serialize(), digest_size=32).digest()
        reference = bytes.fromhex('91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4')
        print('final test')
        print(computed.hex())
        print('91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4')
        assert computed == bytes.fromhex('91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4')
