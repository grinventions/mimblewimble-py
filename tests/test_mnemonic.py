import unittest

from mimblewimble.mnemonic import Mnemonic


class MnemonicTests(unittest.TestCase):
    def test_incorrect_length_entropy(self):
        M = Mnemonic()
        M.mnemonicFromEntropy(bytes([0x0 for i in range(32)]))
        with self.assertRaises(ValueError) as context:
            M.mnemonicFromEntropy(bytes([0x0 for i in range(13)]))
        self.assertTrue(
            'Entropy was of incorrect length.' == str(context.exception))

    def test_mnemonic_from_entropy(self):
        M = Mnemonic()
        phrase = M.mnemonicFromEntropy(bytes([0x0 for i in range(32)]))
        assert phrase == 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'

