import base58

from enum import IntEnum
from typing import List

from mimblewimble.serializer import Serializer

from mimblewimble.helpers.encryption import ageX25519Encrypt, ageX25519Decrypt

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata


SLATEPACK_HEADER = 'BEGINSLATEPACK'
SLATEPACK_FOOTER = 'ENDSLATEPACK'
SLATEPACK_WORD_LENGTH = 15
SLATEPACK_WORDS_PER_LINE = 200


def slatepack_spacing(data: str, word_length=None):
    if word_length is None:
        word_length = SLATEPACK_WORD_LENGTH
    chunks = [
        data[i:i+word_length] for i in range(
            0, len(data), word_length)
    ]
    chunks[-1] = chunks[-1] + '.'
    return chunks


def slatepack_pack(
        data: bytes,
        word_length=None,
        words_per_line=None,
        string_encoding='ascii') -> str:
    encoded = base58.b58encode(data).decode(string_encoding)
    words = [SLATEPACK_HEADER + '.']
    words += slatepack_spacing(encoded, word_length=word_length)
    words += [SLATEPACK_FOOTER + '.']
    packed = ''
    line = []
    if words_per_line is None:
        words_per_line = SLATEPACK_WORDS_PER_LINE
    for word in words:
        if len(line) >= words_per_line:
            packed += ' '.join(line)
            packed += '\n'
            line = []
        line.append(word)
    if len(line) >= 0:
        packed += ' '.join(line)
    packed += '\n'
    return packed


def slatepack_unpack(data: str) -> bytes:
    processed = data.replace(SLATEPACK_HEADER, '')
    processed = processed.replace(SLATEPACK_FOOTER, '')
    processed = processed.replace('.', '')
    processed = processed.replace(' ', '')
    processed = processed.replace('\n', '')
    return base58.b58decode(processed)


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

    def pack(self):
        pass

    @classmethod
    def unpack(self, packed: str):
        unpacked = slatepack_unpack(packed)
        return SlatepackMessage.deserialize(unpacked)

    @classmethod
    def unpack_encrypted(self, packed) -> bytes:
        return slatepack_unpack(packed)

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

    def decryptPayload(self, payload, key):
        return ageX25519Decrypt(payload, key)

    def decrypt(self, serializer: Serializer):
        version = SlatepackVersion.deserialize(serializer)
        emode = EMode(int.from_bytes(serializer.read(1), 'big'))

        opt_flags = serializer.read(2)
        opt_fields_len = int.from_bytes(serializer.read(4), 'big')

        metadata = SlatepackMetadata()
        if opt_flags & 0x01 == 0x01:
            sender = SlatepackAddress.deserialize(serializer)
            metadata = SlatepackMetadata(sender=sender)

        payload_size = int.from_bytes(serializer.read(8), 'big')
        payload = serializer.read(payload_size)

        if emode == EMode.ENCRYPTED:
            decrypted_payload = self.decryptPayload(payload, key)
            return SlatepackMessage(version, metadata, emode, decrypted_payload)

        return SlatepackMessage(version, metadata, emode, payload)

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
