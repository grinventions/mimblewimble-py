from enum import IntEnum
from typing import List

from mimblewimble.serializer import Serializer

from mimblewimble.helpers.encryption import ageX25519Encrypt, ageX25519Decrypt

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata


class EMode(IntEnum):
    PLAINTEXT = 0
    ENCRYPTED = 1


class SlatepackMessage:
    def __init__(
            self,
            version: SlatepackVersion,
            metadata: SlatepackMetadata,
            emode: EMode,
            payload: bytes):
        self.version = version
        self.metadata = metadata
        self.emode = emode
        self.payload = payload

    def serialize(self):
        serializer = Serializer()
        self.version.serialize(serializer)

    def deserialize(self, serializer: Serializer):
        version = int.from_bytes(serializer.read(1), 'big')

    def encryptPayload(self, recipients: List[SlatepackAddress]):
        keys = [
            recipient.toAge() for recipient in recipients
        ]
        return ageX25519Encrypt(self.payload, keys)

    def encrypt(self):
        serializer = Serializer()

        serializer.write(int(self.emode).to_bytes(1, 'big'))

        opt_flags = 0x00
        if self.emode == EMode.PLAINTEXT and self.sender is not None:
            opt_flags |= 0x01
        serializer.write(opt_flags.to_bytes(2, 'big'))

        if opt_flags & 0x01 == 0x01:
            self.sender.serialize(serializer)

        if self.emode == EMode.PLAINTEXT:
            serializer.write(self.payload)
        else:
            serializer.write(self.encryptPayload(self.metadata.recipients))

        return serializer.readall()

    # TODO accepts key as argument
    def decryptPayload(self):
        # TODO
        ageED25519Decrypt(ciphertext, ed25519sk, derived_secret)
        pass

    def __str__(self):
        return ''

    def toJSON(self, testnet=False):
        slatepack = {
            'slatepack': [self.version.major, self.version.minor],
            'mode': int(self.emode)
        }
        version = str(self.version)
        if self.emode == EMode.PLAINTEXT:
            slatepack['sender'] = '0'
            if self.metadata.sender is not None:
                slatepack['sender'] = self.metadata.sender.toBech32(testnet=testnet)
            slatepack['payload'] = self.payload.hex()
            return slatepack
        slatepack['payload'] = '' # TODO
        return slatepack
