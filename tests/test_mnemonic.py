import unittest

from mimblewimble.mnemonic import Mnemonic


class MnemonicTests(unittest.TestCase):
    def test_incorrect_length_entropy(self):
        M = Mnemonic()
        M.mnemonicFromEntropy(4327429364, 12)
        with self.assertRaises(ValueError) as context:
            M.mnemonicFromEntropy(4327429364, 13)
        self.assertTrue(
            'Entropy was of incorrect length.' == str(context.exception))
