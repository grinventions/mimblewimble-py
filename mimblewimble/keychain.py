import hmac
import os

from typing import Union

from bip32 import BIP32
from bip_utils import Bech32Encoder
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

from mimblewimble.models.slatepack.address import SlatepackAddress

from mimblewimble.helpers.encryption import ageX25519Decrypt


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

    def deriveX25519PublicKey(self, path: str):
        ed25519_pk = self.deriveED25519PublicKey(path=path)

        x25519_pk = bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)

        return x25519_pk

    def deriveX25519SecretKey(self, path: str):
        # get the seed
        # seed_blake = self.deriveED25519Seed(path)

        # get the ed25519 public key and public key from it
        # ed25519_pk, ed25519_sk = bindings.crypto_sign_seed_keypair(seed_blake)

        ed25519_sk = self.deriveED25519SecretKey(path=path)

        # construct the x25519 secret key
        x25519_sk = bindings.crypto_sign_ed25519_sk_to_curve25519(ed25519_sk)

        return x25519_sk

    def deriveAgeSecretKey(self, path: str):
        x25519_sk = self.deriveX25519SecretKey(path)

        age_secret_key = Bech32Encoder.Encode('age-secret-key-', x25519_sk)
        return age_secret_key.upper()

    def signED25519(self, message: bytes, path: str) -> bytes:
        sk = self.deriveED25519SecretKey(path)
        signature_message = bindings.crypto_sign(message, sk)
        del sk
        # first 64 bytes is signature, then message, this is just how nacl works
        # but grin only needs signature
        signature = signature_message[0:64]
        return signature

    @classmethod
    def verifyED25519(
            self,
            public_key: Union[bytes, str],
            signature: bytes,
            message: bytes) -> bool:
        public_key_bytes = public_key
        if isinstance(public_key, str):
            public_key_bytes = KeyChain.slatepackAddressToED25519PublicKey(
                public_key)
        signature_message = signature + message
        recovered = bindings.crypto_sign_open(signature_message, public_key_bytes)
        return recovered == message

    def ageDecrypt(
            self,
            ciphertext: bytes,
            path: str):
        age_secret_key = self.deriveAgeSecretKey(path)

        return ageX25519Decrypt(
            ciphertext, age_secret_key)

    def deriveSlatepackAddress(self, path: str, testnet=False):
        pk = self.deriveED25519PublicKey(path)
        slatepack_address = SlatepackAddress(pk)
        return slatepack_address.toBech32(testnet=testnet)

    def deriveOnionAddress(self, path: str):
        pk = self.deriveED25519PublicKey(path)
        return KeyChain.slatepackAddressToOnion(pk)

    @classmethod
    def slatepackAddressToED25519PublicKey(
            self, address: str, testnet=False) -> bytes:
        slatepack_address = SlatepackAddress.fromBech32(
            address, testnet=testnet)
        return slatepack_address.toED25519()

    @classmethod
    def slatepackAddressToOnion(self, public_key: Union[bytes, str]):
        slatepack_address = SlatepackAddress(public_key)
        if isinstance(public_key, str):
            slatepack_address = SlatepackAddress.fromBech32(
                public_key)
        return slatepack_address.toOnion(version=3)

    def rewindRangeProof(
            self,
            commitment: Commitment,
            rangeproof: RangeProof,
            bulletproof_type: EBulletproofType):
        b = Bulletproof()
        try:
            if bulletproof_type == EBulletproofType.ORIGINAL:
                nonce = KeyChain.createNonce(
                    commitment, self.bulletproof_nonce)
                rewind_result = b.rewindProof(
                    commitment, rangeproof, nonce)
            elif bulletproof_type == EBulletproofType.ENHANCED:
                pks = PublicKeys()
                master_public_key = pks.calculatePublicKey(self.master_key)

                rewind_nonce_hash = SecretKey(blake2b(
                    master_public_key.getBytes(),
                    digest_size=32).digest())

                rewind_result = b.rewindProof(
                    commitment,
                    rangeproof,
                    KeyChain.createNonce(commitment, rewind_nonce_hash))
            return rewind_result
        finally:
            del b  # just to make sure secp256k1-zkp context is freed
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
            generated_range_proof = b.generateRangeProof(
                amount, blinding_factor, nonce, nonce, proof_message)
            del b # just to make sure secp256k1-zkp context is freed
            return generated_range_proof
        elif bulletproof_type == EBulletproofType.ENHANCED:
            private_nonce_hash = SecretKey(blake2b(
                self.master_key.getBytes(),
                digest_size=32).digest())

            pks = PublicKeys()
            master_public_key = pks.calculatePublicKey(self.master_key)

            rewind_nonce_hash = SecretKey(blake2b(
                master_public_key.getBytes(),
                digest_size=32).digest())

            generated_range_proof = b.generateRangeProof(
                amount,
                blinding_factor,
                KeyChain.createNonce(commitment, private_nonce_hash),
                KeyChain.createNonce(commitment, rewind_nonce_hash),
                proof_message)
            del b # just to make sure secp256k1-zkp context is freed
            return generated_range_proof
        del b # just to make sure secp256k1-zkp context is freed
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
