import os

from nacl import bindings

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from hashlib import blake2b, pbkdf2_hmac

from bip32 import BIP32
from bip_utils import Bech32Encoder

from mimblewimble.mnemonic import Mnemonic


class Wallet:
    def __init__(self, encrypted_seed=None, salt=None, nonce=None, master_seed=None, master_seed_rem=None):
        self.encrypted_seed = encrypted_seed
        self.salt = salt
        self.nonce = nonce
        self.master_seed = master_seed # 32 bytes
        self.master_seed_rem = master_seed_rem # TODO find what it represents, 16 bytes


    def encryptWallet(self, passphrase, salt=None, nonce=None):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')
        if salt is not None:
            self.salt = salt
        if nonce is not None:
            self.nonce = nonce
        # compute encrypted_seed from master_seed
        key = pbkdf2_hmac('sha512', bytes(passphrase, 'utf-8'), salt, 100)
        cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=nonce)
        self.encrypted_seed = cipher.encrypt(self.master_seed + self.master_seed_rem)


    def shieldWallet(self, salt=None, nonce=None, passphrase=None):
        if None in [self.encrypted_seed, self.salt, self.nonce]:
            raise Exception('The wallet cannot be shielded as password is not set')
        self.master_seed = None
        self.master_seed_rem = None


    def unshieldWallet(self, passphrase, salt=None, nonce=None):
        if self.salt is None and salt is None:
            raise Exception('Missing salt')
        elif self.salt is None and salt is not None:
            self.salt = salt
        if self.nonce is None and nonce is None:
            raise Exception('Missing nonce')
        elif self.nonce is None and nonce is not None:
            self.nonce = nonce
        # compute master_seed from encrypted_seed
        key = pbkdf2_hmac('sha512', bytes(passphrase, 'utf-8'), salt, 100)
        cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=nonce)
        plaintext = cipher.decrypt(self.encrypted_seed)
        self.master_seed = plaintext[:32]
        self.master_seed_rem = plaintext[32:]
        del plaintext


    def getSeedPhrase(self):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')
        M = Mnemonic()
        return M.mnemonicFromEntropy(self.master_seed)


    def getSlatepackAddress(self, path=None, testnet=False):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')
        bip32 = BIP32.from_seed(self.master_seed)
        sk_der = bip32.get_privkey_from_path(path)
        sk_der_blake = blake2b(sk_der, digest_size=64).digest()
        pk = bindings.crypto_sign_ed25519_sk_to_pk(sk_der_blake)
        return Bech32Encoder.Encode('grin', pk)


    @classmethod
    def initialize(self):
        # TODO
        pass


    @classmethod
    def fromSeedPhrase(self, phrase: str):
        M = Mnemonic()
        master_seed = M.entropyFromMnemonic(phrase)
        return Wallet(master_seed=master_seed)


    @classmethod
    def fromEncryptedSeed(encrypted_seed_hex: str, salt: str, nonce: str, passphrase: str):
        # TODO
        pass

