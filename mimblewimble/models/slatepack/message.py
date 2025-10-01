import base58
import hashlib

from enum import IntEnum
from typing import List

from mimblewimble.serializer import Serializer
from mimblewimble.codecs import Base64Codec

from mimblewimble.helpers.encryption import ageX25519Encrypt, ageX25519Decrypt

from mimblewimble.slatebuilder.slate import Slate

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

        # if encrypted, payload contains all slate info
        # if decrypted, the version and metadata are ommitted
        self.payload = payload

    def pack(self, word_length=None, words_per_line=None, string_encoding='ascii'):
        preimage = self.serialize()

        hashed = hashlib.sha256(preimage).digest()
        hashed = hashlib.sha256(hashed).digest()
        checksum = hashed[0:4]

        s = checksum + preimage

        packed = slatepack_pack(
            s,
            word_length=word_length,
            words_per_line=words_per_line,
            string_encoding=string_encoding)
        return packed

    @classmethod
    def unpack(self, packed: str):
        unpacked = slatepack_unpack(packed)

        s = Serializer()
        s.write(unpacked)

        error_check_code = s.read(4)
        preimage = s.readremaining()

        hashed = hashlib.sha256(preimage).digest()
        hashed = hashlib.sha256(hashed).digest()
        checksum = hashed[0:4]

        if checksum != error_check_code:
            raise ValueError('Invalid slatepack checkum')

        return preimage

    def serialize(self):
        serializer = Serializer()

        self.version.serialize(serializer)
        serializer.write(int(self.emode).to_bytes(1, 'big'))

        opt_flags = 0x00
        if self.emode == EMode.PLAINTEXT and self.metadata.sender is not None:
            opt_flags |= 0x01

        if self.emode == EMode.PLAINTEXT and len(self.metadata.recipients) > 0:
            opt_flags |= 0x02

        serializer.write(opt_flags.to_bytes(2, 'big'))

        opt_fields_len = 0 # what should it be?
        serializer.write(opt_fields_len.to_bytes(4, 'big'))

        if opt_flags & 0x01 == 0x01:
            self.metadata.sender.serialize(serializer)

        if opt_flags & 0x02 == 0x02:
            num_recipients = len(self.metadata.recipients)
            serializer.write(num_recipients.to_bytes(2, 'big'))
            for recipient in self.metadata.recipients:
                recipient.serialize(serializer)

        payload_size_int = len(self.payload)
        payload_size_bin = payload_size_int.to_bytes(8, 'big') # TODO that was missing
        serializer.write(payload_size_bin)

        serializer.write(self.payload)

        return serializer.readall()

    @classmethod
    def deserialize(self, unpacked: bytes):
        serializer = Serializer()
        serializer.write(unpacked)

        version = SlatepackVersion.deserialize(serializer)
        emode = EMode(int.from_bytes(serializer.read(1), 'big'))

        opt_flags_bin = serializer.read(2)
        opt_flags = int.from_bytes(opt_flags_bin, 'big')

        opt_fields_len = int.from_bytes(serializer.read(4), 'big')

        sender = None
        recipients = []
        if opt_flags & 0x01 == 0x01:
            sender = SlatepackAddress.deserialize(serializer)

        if opt_flags & 0x02 == 0x02:
            recipients = []
            num_recipients = int.from_bytes(serializer.read(2), 'big')
            for i in range(num_recipients):
                recipient = SlatepackAddress.deserialize(serializer)
                recipients.append(recipient)

        metadata = SlatepackMetadata(sender=sender, recipients=recipients)

        payload_size = int.from_bytes(serializer.read(8), 'big')
        payload = serializer.read(payload_size)

        return SlatepackMessage(version, metadata, emode, payload)

    def armor(self):
        pass

    @classmethod
    def unarmor(self, armored_slatepack: str):
        unpacked = SlatepackMessage.unpack(armored_slatepack)
        return SlatepackMessage.deserialize(unpacked)

    def is_encrypted(self):
        return self.emode != EMode.PLAINTEXT

    def getPayload(self) -> bytes:
        return self.payload

    def setPayload(self, payload: bytes, emode: EMode):
        self.emode = emode
        if self.emode == EMode.PLAINTEXT:
            s = Serializer()
            s.write(payload)

            self.metadata = SlatepackMetadata.deserialize(s)
            self.payload = s.readremaining()
        else:
            self.metadata = None
            self.payload = payload

    def getSlate(self):
        if self.emode == EMode.ENCRYPTED:
            raise Exception(
                'requesting a slate but payload is still encrypted')
        return Slate.deserialize(self.payload)

    def encryptPayload(self, recipients: List[SlatepackAddress]):
        if self.emode != EMode.PLAINTEXT:
            raise ValueError(
                'requesting encrypting an already encrypted payload in SlatepackMessage')
        keys = [
            recipient.toAge() for recipient in recipients
        ]

        serializer = Serializer()

        '''
        opt_flags = 0x01
        if len(self.metadata.recipients) > 0:
            opt_flags |= 0x02
        serializer.write(opt_flags.to_bytes(2, 'big'))
        self.sender.serialize(serializer)
        if len(self.metadata.recipients) > 0:
            num_recipients = len(self.metadata.recipients)
            serializer.write(num_recipients.to_bytes(2, 'big'))
            for recipient in self.metadata.recipients:
                recipient.serialize(serializer)
        '''
        self.metadata.serialize(serializer)
        serializer.write(self.payload)

        '''
        self.metadata.serialize(s)
        s.write(self.payload)
        # serialized = self.payload
        '''

        serialized = serializer.readall()

        self.payload = ageX25519Encrypt(serialized, keys)
        self.emode = EMode.ENCRYPTED

    def decryptPayload(self, age_secret_key: str):
        if self.emode != EMode.ENCRYPTED:
            raise ValueError(
                'requesting decrypting an already decrypted payload in SlatepackMessage')
        decrypted_payload = ageX25519Decrypt(
            self.payload, age_secret_key)

        s = Serializer()
        s.write(decrypted_payload)

        self.metadata = SlatepackMetadata.deserialize(s)
        self.emode = EMode.PLAINTEXT
        self.payload = s.readremaining()

    '''
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

    def decrypt(self, serializer: Serializer):
        version = SlatepackVersion.deserialize(serializer)
        emode = EMode(int.from_bytes(serializer.read(1), 'big'))

        opt_flags = int.from_bytes(serializer.read(2), 'big')
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
    '''

    def __str__(self):
        return ''

    def toJSON(self, testnet=False, codec=Base64Codec, encoding='utf-8'):
        payload = codec.encode(self.payload, encoding=encoding)
        slatepack = {
            'slatepack': [self.version.major, self.version.minor],
            'mode': int(self.emode),
            'payload': payload
        }
        version = str(self.version)
        if self.emode == EMode.PLAINTEXT:
            slatepack['sender'] = '0'
            if self.metadata.sender is not None:
                slatepack['sender'] = self.metadata.sender.toBech32(testnet=testnet)
            return slatepack
        return slatepack
