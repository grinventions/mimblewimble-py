import hashlib
import json

from hashlib import pbkdf2_hmac

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
        checksumBits = int(entropyBits / 32)
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
        lhs = hashlib.sha256(entropy).digest()[0]
        checksum = (lhs >> (8 - checksumBits)) & mask

        for i in reversed(range(1, checksumBits+1)):
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
        words = wallet_words.split(' ')

        numWords = len(words)

        if numWords < 12 or numWords > 24 or numWords % 3 != 0:
            raise ValueError('Invalid number of words provided.')

        wordIndices = [None for i in range(numWords)]

        for i, word in enumerate(words):
            try:
                j = self.words.index(word)
            except ValueError:
                raise ValueError('Word not found: ' + word)

            wordIndices[i] = j;

        checksumBits = int(numWords / 3)
        mask = (1 << checksumBits) - 1
        expectedChecksum = wordIndices[-1] & mask;

        dataLength = int((((11 * numWords) - checksumBits) / 8) - 1)

        entropy = [0x0 for j in range(dataLength + 1)]
        entropy[-1] = wordIndices[-1] >> checksumBits

        loc = 11 - checksumBits

        for i in reversed(range(1, numWords)):
            for k in range(11):
                bit = 1
                if wordIndices[i - 1] & (1 << k) == 0:
                    bit = 0
                entropy[dataLength - int(loc / 8)] |= bit << (loc % 8)
                loc += 1

        entropy = bytes(entropy)

        lhs = hashlib.sha256(entropy).digest()[0]
        actualChecksum = (lhs >> (8 - checksumBits)) & mask

        if actualChecksum != expectedChecksum:
            raise ValueError('Invalid checksum.')

        return entropy


    def toSeed(self, entropy, passphrase=''):
        salt = bytes('mnemonic' + passphrase, 'utf-8')
        dk = pbkdf2_hmac('sha512', entropy, salt, 2048)
        return dk.hex()





