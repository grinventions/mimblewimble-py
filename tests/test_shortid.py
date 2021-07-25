import unittest

from mimblewimble.models.short_id import ShortId


class ShortIdTest(unittest.TestCase):
    def test_case1(self):
        _hash = bytes.fromhex('81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c')
        _blockHash = (0).to_bytes(32, byteorder='big')
        _nonce = 0
        shortId = ShortId.create(_hash, _blockHash, _nonce)
        assert shortId.getId() == int.from_bytes(bytes.fromhex('4cc808b62476'), byteorder='little')


    def test_case2(self):
        _hash = bytes.fromhex('3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673')
        _blockHash = (0).to_bytes(32, byteorder='big')
        _nonce = 5
        shortId = ShortId.create(_hash, _blockHash, _nonce)
        assert shortId.getId() == int.from_bytes(bytes.fromhex('02955a094534'), byteorder='little')


    def test_case3(self):
        _hash = bytes.fromhex('3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673')
        _blockHash = bytes.fromhex('81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c')
        _nonce = 5
        shortId = ShortId.create(_hash, _blockHash, _nonce)
        assert shortId.getId() == int.from_bytes(bytes.fromhex('3e9cde72a687'), byteorder='little')
