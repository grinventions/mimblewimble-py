import unittest
import os

from mimblewimble.mnemonic import Mnemonic


class MnemonicTests(unittest.TestCase):
    def test_incorrect_length_entropy(self):
        M = Mnemonic()
        M.mnemonicFromEntropy(bytes([0x0 for i in range(32)]))
        with self.assertRaises(ValueError) as context:
            M.mnemonicFromEntropy(bytes([0x0 for i in range(13)]))
        self.assertTrue(
            'Entropy was of incorrect length.' == str(context.exception))

    def test_mnemonic(self):
        M = Mnemonic()
        entropy = bytes([0x0 for i in range(32)])
        phrase = M.mnemonicFromEntropy(entropy)
        assert phrase == 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon again'
        assert M.entropyFromMnemonic(phrase) == entropy


    def test_mnemonic_random(self):
        M = Mnemonic()
        entropy = os.urandom(32)
        phrase = M.mnemonicFromEntropy(entropy)
        assert M.entropyFromMnemonic(phrase) == entropy

