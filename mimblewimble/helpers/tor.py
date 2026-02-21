import base64
import hashlib

from nacl import bindings


class TorAddress:
    def __init__(self, public_key):
        self.public_key = public_key

    def toOnion(self, version=3):
        version_bytes = version.to_bytes(1, "big")
        checksum = TorAddress.checksum(self.public_key, version_bytes)
        address = base64.b32encode(
            self.public_key + checksum[0:2] + version_bytes
        ).decode()
        return address.lower() + ".onion"

    @classmethod
    def checksum(self, public_key: bytes, version: bytes):
        preimage = ".onion checksum".encode("ascii")
        preimage += public_key
        preimage += version
        return hashlib.sha3_256(preimage).digest()

    @classmethod
    def parse(self, tor_address):
        without_onion = tor_address.replace(".onion", "").upper()
        decoded = base64.b32decode(without_onion)
        public_key = decoded[0:32]
        check = decoded[32:34]
        version_bytes = decoded[34:35]
        version = int.from_bytes(version_bytes, "big")

        # validate version
        if version != 3:
            raise ValueError("Only V3 .onion addresses supported")

        # validate the public key
        try:
            bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)
        except:
            raise ValueError(".onion address includes invalid ed25519 public key")

        # compute expected checksum
        expected_checksum = TorAddress.checksum(public_key, version_bytes)
        if expected_checksum[0:2] != check:
            raise ValueError(".onion address checksum mismatch")

        return TorAddress(public_key)
