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
            emode: EMode):
        self.version = version
        self.metadata = metadata
        self.emode = emode
        self.payload = None # TODO, bytes type

    def serialize(self, serializer: Serializer):
        pass

    def deserialize(self, serializer: Serializer):
        pass

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

    def toJSON(self):
        pass
