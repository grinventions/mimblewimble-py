from io import BytesIO


class Fee:
    def __init__(self, shift, fee):
        self.shift = shift
        self.fee = fee

    # operators

    def __eq__(self, other):
        return self.fee == other.getFee() and self.shift == other.getShift()

    def __ne__(self, other):
        return self.fee != other.getFee() or self.shift != other.getShift()

    # getters

    def getShift(self):
        return self.shift

    def getFee(self):
        return self.fee

    # serialization / deserialization

    def serialize(self, serializer):
        serializer.write((0).to_bytes(2))
        serializer.write(self.getShift())
        serializer.write(self.getFee().to_bytes(8) >> (32).to_bytes(8))
        serializer.write(self.getFee().to_bytes(32) & 0xffffffff)

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        byteBuffer.read(2)
        shift = byteBuffer.read(8) & 0x0f
        fee = byteBuffer.read(8) << (32).to_bytes(8)
        fee += byteBuffer.read(32)
        return Fee(shift, fee)

    def toJSON(self):
        return int(self.serialize())

    @classmethod
    def fromJSON(self, feeJSON):
        byteBuffer = BytesIO(feeJSON.to_bytes(64))
        return Fee().deserialize(byteBuffer)


