from io import BytesIO


class SecretKey:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.NUM_BYTES = len(seed)

    # operators

    def __eq__(self, other):
        return self.seed == other.seed

    def __ne__(self, other):
        return self.seed != other.seed

    # serialization / deserialization

    def serialize(self, serializer):
        serializer.write(self.seed)

    @classmethod
    def deserialize(self, byteBuffer: BytesIO, NUM_BYTES=32):
        return SecretKey(byteBuffer.read(NUM_BYTES))

