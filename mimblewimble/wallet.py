import os

from Crypto.Cipher import AES


class Wallet:
    def __init__(self, encrypted_seed):
        self.encrypted_seed = encrypted_seed
        self.wallet_seed = None


    @classmethod
    def initialize(self, num_words=24, passphrase=''):
        # entropy bytes
        entropy_bytes = (4 * num_words) / 3
        # wallet seed
        wallet_seed = os.urandom(4)
        # encrypted seed
        IV = bytes.fromhex(passphrase)
        encrypted_seed = AES.new(wallet_seed, AES.MODE_CBC, IV=IV)
        # wallet seed phrase
        # TODO
        # initialize the wallet
        return Wallet(encrypted_seed)

