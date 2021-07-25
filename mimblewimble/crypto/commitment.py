from io import BytesIO


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

    def serialize(self, serializer):
        serializer.write(self.getBytes())

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        return Commitment(byteBuffer.read(33))

    def hex(self):
        return self.commitmentBytes.hex()

    @classmethod
    def fromHex(self, _hex: str):
        return Commitment(bytes.fromhex(_hex))

    def format(self):
        return 'Commitment{' + self.hex() + '}'


