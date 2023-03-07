import hmac
import os

from nacl import bindings

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from hashlib import blake2b, pbkdf2_hmac, sha512

from bip32 import BIP32
from bip_utils import Bech32Encoder

from mimblewimble.serializer import Serializer
from mimblewimble.mnemonic import Mnemonic
from mimblewimble.keychain import KeyChain

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.bulletproof import EBulletproofType
from mimblewimble.crypto.pedersen import Pedersen

from mimblewimble.models.transaction import EOutputFeatures
from mimblewimble.models.transaction import EKernelFeatures
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import TransactionOutput
from mimblewimble.models.transaction import TransactionKernel

from mimblewimble.models.fee import Fee


class Wallet:
    def __init__(self, encrypted_seed=None, salt=None, nonce=None, master_seed=None, tag=None):
        self.encrypted_seed = encrypted_seed
        self.salt = salt
        self.nonce = nonce
        self.master_seed = master_seed # 32 bytes


    def shieldWallet(self, passphrase: str, salt=None, nonce=None):
        if self.master_seed is None:
            raise Exception('The wallet is already shielded')
        if self.salt is None:
            if salt is None:
                self.salt = os.urandom(8)
            else:
                self.salt = salt
        if self.nonce is None:
            if nonce is None:
                self.nonce = os.urandom(12)
            else:
                self.nonce = nonce
        # compute encrypted_seed from master_seed
        key = pbkdf2_hmac('sha512', bytes(passphrase, 'utf-8'), self.salt, 100)
        cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=self.nonce)
        ciphertext = cipher.encrypt(self.master_seed)
        tag = cipher.digest()
        self.encrypted_seed = ciphertext + tag
        self.master_seed = None


    def unshieldWallet(self, passphrase: str, salt=None, nonce=None):
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
        ciphertext = self.encrypted_seed[:32]
        tag = self.encrypted_seed[32:]
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        self.master_seed = plaintext
        del plaintext


    def getSeedPhrase(self):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')
        M = Mnemonic()
        return M.mnemonicFromEntropy(self.master_seed)


    def getEncryptedSeed(self):
        if None in [self.encrypted_seed, self.salt, self.nonce]:
            raise Exception('The wallet is not shielded')
        return {
            'encrypted_seed': self.encrypted_seed.hex(),
            'salt': self.salt.hex(),
            'nonce': self.nonce.hex()
        }


    def getSlatepackAddress(self, path='m/0/1/0', testnet=False):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')

        # I AM VOLDEMORT
        m = hmac.new('IamVoldemort'.encode('utf8'), digestmod=sha512)
        m.update(self.master_seed)
        secret = m.digest()

        # derive the seed at the path
        bip32 = BIP32(chaincode=secret[32:], privkey=secret[:32])
        sk_der = bip32.get_privkey_from_path(path)

        # compute the blake2 hash of that key and that is ed25519 seed
        seed_blake = blake2b(sk_der, digest_size=32).digest()

        # get the ed25519 secret key and public key from it
        pk, sk = bindings.crypto_sign_seed_keypair(seed_blake)

        # compute the slatepack address
        network = 'grin'
        if testnet:
            network = 'tgrin'
        slatepack_address = Bech32Encoder.Encode(network, pk)

        return slatepack_address


    def createCoinbase(self, amount, path='m/0/1/0'):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')

        # instantiate the keychain for this wallet seed
        keychain = KeyChain.fromSeed(self.master_seed)

        # we will be needing Pedersen commitments
        # and signature aggregation
        p = Pedersen()
        agg = AggSig()

        # blinding factor and Pedersend commitment
        blinding_factor = keychain.derivePrivateKeyAmount(
            path, amount)
        commitment = p.commit(amount, blinding_factor)

        # bulletproof
        rangeproof = keychain.generateRangeProof(
            path, amount, commitment,
            blinding_factor, EBulletproofType.ENHANCED)

        # add the commitments
        transparent_factor = BlindingFactor(bytes([0x00 for j in range(32)]))
        transparent_commitment = p.commit(amount, transparent_factor)
        kernel_commitment = p.commitSum([commitment], [transparent_commitment])

        # build the output
        transaction_output = TransactionOutput(
            EOutputFeatures.COINBASE_OUTPUT,
            commitment,
            rangeproof)
        serializer = Serializer()

        # build the coinbase signature
        message = blake2b(
            EKernelFeatures.COINBASE_KERNEL.to_bytes(1, 'big'),
            digest_size=32).digest()
        coinbase_signature = agg.buildSignature(
            blinding_factor, kernel_commitment, message)

        # build the kernel
        shift = 0
        fee = 0
        transaction_kernel = TransactionKernel(
            EKernelFeatures.COINBASE_KERNEL,
            Fee(shift, fee),
            0,
            kernel_commitment,
            coinbase_signature)

        # clean-up
        del p
        del agg

        # return the result
        return transaction_kernel, transaction_output, path


    @classmethod
    def initialize(self):
        master_seed = os.urandom(32)
        return Wallet(master_seed=master_seed)


    @classmethod
    def fromSeedPhrase(self, phrase: str):
        M = Mnemonic()
        master_seed = M.entropyFromMnemonic(phrase)
        return Wallet(master_seed=master_seed)


    @classmethod
    def fromEncryptedSeedDict(self, seed: dict, passphrase=None):
        return self.fromEncryptedSeed(
            seed['encrypted_seed'], seed['salt'], seed['nonce'],
            passphrase=passphrase)


    @classmethod
    def fromEncryptedSeed(
            self, encrypted_seed_hex: str, salt_hex: str, nonce_hex: str,
            passphrase=None):
        encrypted_seed = bytes.fromhex(encrypted_seed_hex)
        nonce = bytes.fromhex(nonce_hex)
        salt = bytes.fromhex(salt_hex)
        w = Wallet(encrypted_seed=encrypted_seed, salt=salt, nonce=nonce)
        if passphrase is not None:
            w.unshieldWallet(passphrase, nonce=nonce, salt=salt)
        return w
