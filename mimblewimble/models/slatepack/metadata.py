from typing import List

from mimblewimble.serializer import Serializer

from mimblewimble.models.slatepack.address import SlatepackAddress


class SlatepackVersion:
    def __init__(self, major, minor):
        self.major = major
        self.minor = minor

    def serialize(self, serializer: Serializer):
        serializer.write(self.major.to_bytes(1, 'big'))
        serializer.write(self.minor.to_bytes(1, 'big'))

    @classmethod
    def deserialize(self, serializer: Serializer):
        major = int.from_bytes(serializer.read(1), 'big')
        minor = int.from_bytes(serializer.read(1), 'big')
        return SlatepackVersion(major, minor)

    def __str__(self):
        return '{0}:{1}'.format(str(self.major), str(self.minor))


class SlatepackMetadata:
    def __init__(
            self, sender: SlatepackAddress, recipients: List[SlatepackAddress]):
        self.sender = sender
        self.recipients = recipients

    def serialize(self, serializer: Serializer):
        pass

    @classmethod
    def deserialize(self, serializer: Serializer):
        pass

    def encrypt(self):
        pass

    def decrypt(self):
        pass
