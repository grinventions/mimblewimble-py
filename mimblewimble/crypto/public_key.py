from io import BytesIO


class PublicKey:
    def __init__(self, key: bytes):
        self.compressed_key = key

    # getters and setters

    def getBytes(self):
        return self.compressed_key

    # operators

    def __eq__(self, other):
        return self.compressed_key == other.compressed_key

    def __ne__(self, other):
        return self.compressed_key != other.compressed_key

    def __len__(self):
        return len(self.compressed_key)

    # serialization / deserialization

    def serialize(self, serializer):
        serializer.write(self.compressed_key)

    @classmethod
    def deserialize(self, byteBuffer: BytesIO, NUM_BYTES=33):
        return PublicKey(byteBuffer.read(NUM_BYTES))

    @classmethod
    def fromHex(self, _hex: str):
        return PublicKey(bytes.fromhex(_hex))

    def format(self):
        return 'PublicKey{' + self.compressed_key.hex() + '}'

