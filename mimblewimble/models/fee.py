from mimblewimble.serializer import Serializer


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

    def serialize(self, serializer: Serializer):
        serializer.write((0).to_bytes(2, 'big'))
        serializer.write(self.getShift().to_bytes(1, 'big'))
        serializer.write((self.getFee() >> 32).to_bytes(1, 'big'))
        serializer.write((self.getFee() & 0xffffffff).to_bytes(4, 'big'))

    @classmethod
    def deserialize(self, serializer: Serializer):
        serializer.read(2)
        shift = int.from_bytes(serializer.read(1), 'big') & 0x0f
        fee = int.from_bytes(serializer.read(1), 'big') << 32
        fee += int.from_bytes(serializer.read(4), 'big')
        return Fee(shift, fee)

    def toJSON(self):
        return int(self.serialize())

    @classmethod
    def fromJSON(self, feeJSON):
        byteBuffer = BytesIO(feeJSON.to_bytes(64))
        return Fee().deserialize(byteBuffer)

    @classmethod
    def fromInt(self, fee: int):
        return Fee(0, fee)


