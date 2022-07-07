import json

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

    def mnemonicFromEntropy(self, entropy: int, entropy_len: int):
        if entropy_len % 4 != 0:
            raise ValueError('Entropy was of incorrect length.')
        pass


    def entropyFromMnemonic(self, wallet_words: str):
        # TODO
        pass
