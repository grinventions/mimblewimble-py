import unittest

from mimblewimble.short_id import ShortId


class ShortIdTest(unittest.TestCase):
    def test_case1(self):
        _hash = bytes.fromhex('81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c')
        _blockHash = 0
        _nonce = 0
        shortId = ShortId.create(_hash, _blockHash, _nonce)
        siphash = bytes.fromhex('4cc808b62476')
        ref = int.from_bytes(siphash, byteorder='little')
        assert shortId.getId() == int.from_bytes(bytes.fromhex('4cc808b62476'), byteorder='little')
