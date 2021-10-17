from mimblewimble.serializer import Serializer


class Commitment:
    def __init__(self, commitmentBytes: bytes):
        self.commitmentBytes = commitmentBytes

    # operators

    def __lt__(self, other):
        return self.getBytes() < other.getBytes()

    def __eq__(self, other):
        return self.getBytes() == other.getBytes()

    def __ne__(self, other):
        return self.getBytes() != other.getBytes()

    # getters

    def getBytes(self):
        return self.commitmentBytes

    def __int__(self):
        return int(self.commitmentBytes)

    # serialization / deserialization

    def serialize(self, serializer: Serializer):
        assert len(self.getBytes()) == 33
        serializer.write(self.getBytes())

    @classmethod
    def deserialize(self, serializer: Serializer):
        return Commitment(serializer.read(33))

    def hex(self):
        return self.getBytes().hex()

    @classmethod
    def fromHex(self, _hex: str):
        return Commitment(bytes.fromhex(_hex))

    def toJSON(self):
        return self.hex()

    def format(self):
        return 'Commitment{' + self.hex() + '}'


