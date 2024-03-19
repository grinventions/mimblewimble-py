import os
import base64
import hashlib

from bip_utils import Bech32Encoder, Bech32Decoder

from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from age.keys.agekey import AgePublicKey

from mimblewimble.serializer import Serializer
from mimblewimble.helpers.tor import TorAddress


class SlatepackAddress:
    def __init__(self, ed25519_pk: bytes):
        self.ed25519_pk = ed25519_pk

    def toED25519(self):
        return self.ed25519_pk

    def toX25519(self):
        x25519_pk = crypto_sign_ed25519_pk_to_curve25519(self.ed25519_pk)
        return X25519PublicKey.from_public_bytes(x25519_pk)

    def toAge(self):
        x25519_pk = self.toX25519()
        return AgePublicKey(x25519_pk)

    def toBech32(self, testnet=False):
        public_key = self.toED25519()
        # compute the slatepack address
        network = 'grin'
        if testnet:
            network = 'tgrin'
        slatepack_address = Bech32Encoder.Encode(network, public_key)
        return slatepack_address

    # https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2013
    # base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    def toOnion(self, version=3):
        public_key_bytes = self.toED25519()
        tor = TorAddress(public_key_bytes)
        return tor.toOnion(version=version)

    def toNostr(self):
        pass # TODO

    def serialize(self, serializer: Serializer):
        address = self.toBech32()
        address_length = len(address)
        serializer.write(address_length.to_bytes(1, 'big'))
        serializer.writeString(address)

    @classmethod
    def deserialize(self, serializer: Serializer):
        address_length = int.from_bytes(serializer.read(1), 'big')
        address = serializer.readString(address_length)
        return SlatepackAddress.fromBech32(address)

    @classmethod
    def fromBech32(self, address: str, testnet=False):
        # compute the slatepack address
        network = 'grin'
        if testnet:
            network = 'tgrin'
        public_key = Bech32Decoder.Decode(network, address)
        return SlatepackAddress(public_key)

    @classmethod
    def random(self):
        public_key = os.urandom(32)
        return SlatepackAddress(public_key)
