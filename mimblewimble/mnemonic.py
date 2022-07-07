import hashlib
import json

from math import ceil

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from mimblewimble import static


class Mnemonic:
    def __init__(self):
        # load the wordlist
        f = pkg_resources.open_binary(static, 'wordlist.json')
        self.words = json.load(f)

    def mnemonicFromEntropy(self, entropy: bytes):
        entropy_len = len(entropy)

        if entropy_len % 4 != 0:
            raise ValueError('Entropy was of incorrect length.')

        entropyBits = int(entropy_len * 8)
        checksumBits = int(entropy_len / 32)
        numWords = ceil((entropyBits + checksumBits) / 11)

        wordIndices = [0x0 for j in range(numWords)]

        loc = 0
        for i in range(entropy_len):
            byte = entropy[i]
            for j in reversed(range(1, 9)):
                bit = 1
                if (byte & (1 << (j - 1))) == 0:
                    bit = 0
                wordIndices[int(loc / 11)] |= bit << (10 - (loc % 11))
                loc += 1

        mask = ((1 << checksumBits) - 1)
        lhs = int.from_bytes(hashlib.sha256(entropy).digest(), 'big')
        checksum = (lhs >> (8 - checksumBits)) & mask

        for i in reversed(range(1, checksumBits)):
            bit = 1
            if (checksum & (1 << (i - 1))) == 0:
                bit = 0
            wordIndices[int(loc / 11)] |= bit << (10 - (loc % 11))
            loc += 1

        phrase = ''
        for i in range(numWords):
            if i > 0:
                phrase += ' '
            phrase += self.words[wordIndices[i]]

        return phrase



    def entropyFromMnemonic(self, wallet_words: str):
        # TODO
        pass
