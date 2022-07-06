try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from mimblewimble import static


class Mnemonic:
    def __init__(self, entropy: int):
        # load the wordlist
        filename = pkg_resources.open_binary(static, 'wordlist.json')
        with open(filename, "r") as f:
            self.words = json.load(f)

        def mnemonicFromEntropy(entropy: int):
            # TODO
            pass


        def def entropyFromMnemonic(wallet_words: str):
            # TODO
            pass
