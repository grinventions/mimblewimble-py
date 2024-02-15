import hmac
import os

from typing import Union

from bip32 import BIP32
from bip_utils import Bech32Encoder, Bech32Decoder
from hashlib import blake2b, pbkdf2_hmac, sha512

from nacl import bindings
from nacl.signing import SigningKey, VerifyKey

from mimblewimble.crypto.bulletproof import EBulletproofType

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.public_keys import PublicKeys
from mimblewimble.crypto.rangeproof import RangeProof
from mimblewimble.crypto.pedersen import Pedersen

from mimblewimble.crypto.bulletproof import EBulletproofType
from mimblewimble.crypto.bulletproof import ProofMessage
from mimblewimble.crypto.bulletproof import RewoundProof
from mimblewimble.crypto.bulletproof import Bulletproof

from mimblewimble.helpers.tor import TorAddress


class KeyChain:
    def __init__(self, master_key: bytes, bulletproof_nonce: SecretKey):
        self.master_key = master_key
        self.bulletproof_nonce = bulletproof_nonce

    def derivePrivateKey(self, path: str):
        # derive the seed at the path
        master_key = self.master_key.getBytes()
        bip32 = BIP32(
            chaincode=master_key[32:], privkey=master_key[:32])
        sk = bip32.get_privkey_from_path(path)
        return SecretKey(sk)

    def derivePrivateKeyAmount(self, path: str, amount: int):
        p = Pedersen()
        sk = self.derivePrivateKey(path)
        ska = p.blindSwitch(sk, amount)
        return ska

    def deriveED25519Seed(self, path: str):
        sk_der = self.derivePrivateKey(path)

        # compute the blake2 hash of that key and that is ed25519 seed
        seed_blake = blake2b(sk_der.getBytes(), digest_size=32).digest()
        return seed_blake

    def deriveED25519SecretKey(self, path: str):
        # get the seed
        seed_blake = self.deriveED25519Seed(path)

        # get the ed25519 secret key and public key from it
        pk, sk = bindings.crypto_sign_seed_keypair(seed_blake)
        return sk

    def deriveED25519PublicKey(self, path: str):
        # get the seed
        seed_blake = self.deriveED25519Seed(path)

        # get the ed25519 public key and public key from it
        pk, sk = bindings.crypto_sign_seed_keypair(seed_blake)
        return pk

    def signED25519(self, message: bytes, path: str) -> bytes:
        sk = self.deriveED25519SecretKey(path)
        signature = bindings.crypto_sign(message, sk)
        del sk
        return signature

    @classmethod
    def verifyED25519(
            self,
            public_key: Union[bytes, str],
            signature: bytes,
            message: bytes) -> bool:
        public_key_bytes = public_key
        if isinstance(public_key, str):
            public_key_bytes = KeyChain.slatepackAddressToED25519PublicKey(public_key)
        recovered = bindings.crypto_sign_open(signature, public_key_bytes)
        return recovered == message

    def deriveSlatepackAddress(self, path: str, testnet=False):
        pk = self.deriveED25519PublicKey(path)

        # compute the slatepack address
        network = 'grin'
        if testnet:
            network = 'tgrin'
        slatepack_address = Bech32Encoder.Encode(network, pk)

        return slatepack_address

    def deriveOnionAddress(self, path: str):
        pk = self.deriveED25519PublicKey(path)
        return KeyChain.slatepackAddressToOnion(pk)

    @classmethod
    def slatepackAddressToED25519PublicKey(
            self, address: str, testnet=False) -> bytes:
        # compute the slatepack address
        network = 'grin'
        if testnet:
            network = 'tgrin'

        public_key = Bech32Decoder.Decode(network, address)
        return public_key

    @classmethod
    def slatepackAddressToOnion(self, public_key: Union[bytes, str]):
        public_key_bytes = public_key
        if isinstance(public_key, str):
            public_key_bytes = KeyChain.slatepackAddressToED25519PublicKey(public_key)

        # derive the onion address
        tor = TorAddress(public_key_bytes)
        return tor.toOnion(version=3)


    def rewindRangeProof(
            self,
            commitment: Commitment,
            rangeproof: RangeProof,
            bulletproof_type: EBulletproofType):
        b = Bulletproof()
        if bulletproof_type == EBulletproofType.ORIGINAL:
            nonce = KeyChain.createNonce(
                commitment, self.bulletproof_nonce)
            return b.rewindProof(
                commitment, rangeproof, nonce)
        elif bulletproof_type == EBulletproofType.ENHANCED:
            pks = PublicKeys()
            master_public_key = pks.calculatePublicKey(self.master_key)

            rewind_nonce_hash = SecretKey(blake2b(
                master_public_key.getBytes(),
                digest_size=32).digest())

            return b.rewindProof(
                commitment,
                rangeproof,
                KeyChain.createNonce(commitment, rewind_nonce_hash))
        raise ValueError('Unimplemented bulletproof type')


    def generateRangeProof(
            self,
            path: str,
            amount: int,
            commitment: Commitment,
            blinding_factor: SecretKey,
            bulletproof_type: EBulletproofType):

        key_indices = KeyChain.getKeyIndices(path)
        proof_message = ProofMessage.fromKeyIndices(
            key_indices, bulletproof_type)

        b = Bulletproof()
        if bulletproof_type == EBulletproofType.ORIGINAL:
            nonce = KeyChain.createNonce(
                commitment, self.bulletproof_nonce)
            return b.generateRangeProof(
                amount, blinding_factor, nonce, nonce, proof_message)
        elif bulletproof_type == EBulletproofType.ENHANCED:
            private_nonce_hash = SecretKey(blake2b(
                self.master_key.getBytes(),
                digest_size=32).digest())

            pks = PublicKeys()
            master_public_key = pks.calculatePublicKey(self.master_key)

            rewind_nonce_hash = SecretKey(blake2b(
                master_public_key.getBytes(),
                digest_size=32).digest())

            return b.generateRangeProof(
                amount,
                blinding_factor,
                KeyChain.createNonce(commitment, private_nonce_hash),
                KeyChain.createNonce(commitment, rewind_nonce_hash),
                proof_message)
        raise ValueError('Unimplemented bulletproof type')

    @classmethod
    def getKeyIndices(self, path: str):
        key_indices = []
        for v in path.split('/'):
            try:
                i = int(v)
            except:
                continue
            key_indices.append(i)
        return key_indices

    @classmethod
    def createNonce(self, commitment: Commitment, nonce_hash: SecretKey):
        nonce = blake2b(
            commitment.getBytes() + nonce_hash.getBytes(),
            digest_size=32).digest()
        return SecretKey(nonce)

    @classmethod
    def fromSeed(self, master_seed):
        # I AM VOLDEMORT
        m = hmac.new('IamVoldemort'.encode('utf8'), digestmod=sha512)
        m.update(master_seed)
        master_key = SecretKey(m.digest())
        p = Pedersen()
        bulletproof_nonce = p.blindSwitch(master_key, 0)
        return KeyChain(master_key, bulletproof_nonce)

    @classmethod
    def fromRandom(self):
        master_seed = os.urandom(32)
        return KeyChain.fromSeed(master_seed)
