import os

from typing import List
from hashlib import sha256
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from pyrage import decrypt as age_decrypt
from pyrage import encrypt as age_encrypt
from pyrage import x25519 as age_x25519

from age.keys.agekey import AgePublicKey

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


def ageX25519Encrypt(
        plaintext: bytes,
        _recipients: List[str]):
    recipients = []
    for r in _recipients:
        if isinstance(r, AgePublicKey):
            as_str = r.public_string()
        else:
            as_str = r
        recipients.append(as_str)
    recipients = [
        age_x25519.Recipient.from_str(r) for r in recipients]
    return age_encrypt(plaintext, recipients)


def ageX25519Decrypt(
        ciphertext: bytes, age_secret_key: str):
    receiver = age_x25519.Identity.from_str(
        age_secret_key)
    return age_decrypt(ciphertext, [receiver])

