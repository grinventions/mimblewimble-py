import unittest

from mimblewimble.short_id import ShortId


class ShortIdTest(unittest.TestCase):
    def test_case1(self):
        _hash = int(bytes.fromhex('81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c'))
        _blockHash = 0
        _nonce = 0
        shortId = ShortId(blockHash)
        assert shortId.getId() == int(bytes.fromhex('4cc808b62476'))
