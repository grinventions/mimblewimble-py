import os

from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from age.stream import stream_decrypt, stream_encrypt

from age.keys.ed25519 import Ed25519PrivateKey as ageEd25519PrivateKey
from age.keys.ed25519 import Ed25519PublicKey as ageEd25519PublicKey

from age.algorithms.ssh_ed25519 import ssh_ed25519_decrypt_file_key
from age.algorithms.ssh_ed25519 import ssh_ed25519_encrypt_file_key

from hashlib import pbkdf2_hmac
from Crypto.Cipher import ChaCha20_Poly1305


def encrypt(plaintext: bytes, passphrase: bytes, nonce=None, salt=None):
    if salt is None:
        salt = os.urandom(8)
    if nonce is None:
        nonce = os.urandom(12)
    key = pbkdf2_hmac('sha512', passphrase, salt, 100)
    cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    tag = cipher.digest()
    return ciphertext, tag, nonce, salt


def decrypt(
        ciphertext: bytes,
        passphrase: bytes,
        tag: bytes,
        salt: bytes,
        nonce: bytes):
    key = pbkdf2_hmac('sha512', passphrase, salt, 100)
    cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def ageED25519pk(ed25519pk: bytes):
    pk = Ed25519PublicKey.from_public_bytes(ed25519pk)
    return ageEd25519PublicKey(pk)


def ageED25519fingerprint(ed25519pk: bytes):
    ed25519_public_key = ageED25519pk(ed25519pk)
    ed25519_public_key_bin = ed25519_public_key.binary_encoding()
    return sha256(ed25519_public_key_bin).digest()[:4]


def ageED25519sk(ed25519sk: bytes):
    sk = Ed25519PrivateKey.from_private_bytes(ed25519sk)
    return ageEd25519PrivateKey(sk)


def ageED25519Encrypt(plaintext: bytes, ed25519pk: bytes):
    ed25519_public_key = ageED25519pk(ed25519pk)
    return ssh_ed25519_encrypt_file_key(
        ed25519_public_key, plaintext)


def ageED25519Decrypt(
        ciphertext: bytes,
        ed25519sk: bytes,
        derived_secret: bytes, fingerprint=None):
    sk_part = ed25519sk[:32]
    pk_part = ed25519sk[32:]
    ed25519_private_key = ageED25519sk(sk_part)
    if fingerprint is None:
        fingerprint = ageED25519fingerprint(pk_part)
    return ssh_ed25519_decrypt_file_key(
        ed25519_private_key, fingerprint, derived_secret, ciphertext)
