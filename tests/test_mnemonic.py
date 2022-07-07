import unittest

from mimblewimble.mnemonic import Mnemonic


class MnemonicTests(unittest.TestCase):
    def test_incorrect_entropy(self):
        M = Mnemonic()
