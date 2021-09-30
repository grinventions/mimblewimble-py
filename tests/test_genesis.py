from io import BytesIO

import hashlib
import unittest

from mimblewimble.genesis import floonet, mainnet


class GenesisTest(unittest.TestCase):
    def test_genesis(self):
        print('genesis test')
        genesis = mainnet
        # check proof of work hash
        assert genesis.getHash().hex() == '40adad0aec27797b48840aa9e00472015c21baea118ce7a2ff1a82c0f8f5bf82'
        # check serialized block header hash
        serializer = BytesIO()
        genesis.header.serialize(serializer)
        computed = hashlib.blake2b(serializer.getvalue(), digest_size=32).digest()
        computed == bytes.fromhex('6046b08903fa520e693b86e700d6a430b353e767027dd9ed1ccbb7017d0bb4dc') # value extracted from grin++
        # check whole serialized block hash
        computed = hashlib.blake2b(genesis.serialize(), digest_size=32).digest()
        assert computed == bytes.fromhex('6be6f34b657b785e558e85cc3b8bdb5bcbe8c10e7e58524c8027da7727e189ef')

    def test_floonet(self):
        print('floonet test')
        genesis = floonet
        # check proof of work hash
        assert genesis.getHash().hex() == 'edc758c1370d43e1d733f70f58cf187c3be8242830429b1676b89fd91ccf2dab'
        # check serialized block header hash
        serializer = BytesIO()
        genesis.header.serialize(serializer)
        computed = hashlib.blake2b(serializer.getvalue(), digest_size=32).digest()
        computed == bytes.fromhex('2d71d7996a0cf2eda1c357eb11e713e1ef7930de5d293a839c4e4d40e37d3e1d') # value extracted from grin++
        # check whole serialized block hash
        computed = hashlib.blake2b(genesis.serialize(), digest_size=32).digest()
        assert computed == bytes.fromhex('91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4')
