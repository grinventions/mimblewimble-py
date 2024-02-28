from enum import IntEnum

from mimblewimble.serializer import Serializer

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

    # TODO uses recipients pub keys for encryption
    def encryptPayload(self, recipients: List[SlatepackAddress]):
        # TODO
        pass

    # TODO accepts key as argument
    def decryptPayload(self):
        # TODO
        pass

    def __str__(self):
        return ''

    def toJSON(self, testnet=Fasle):
        slatepack = {
            'slatepack': [self.version.major, self.version.minor],
            'mode': int(self.emode)
        }
        version =
        if self.emode == EMode.PLAINTEXT:
            slatepack['sender'] = '0'
            if self.metadata.sender is not None:
                slatepack['sender'] = self.metadata.sender.toBech32(testnet=testnet)
            slatepack['payload'] = self.payload.hex()
            return slatepack
        slatepack['payload'] = '' # TODO
        return slatepack
