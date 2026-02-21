from mimblewimble.serializer import Serializer


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

    def serialize(self, serializer: Serializer):
        serializer.write(self.compressed_key)

    @classmethod
    def deserialize(self, serializer: Serializer, NUM_BYTES=33):
        compressed_key = serializer.read(NUM_BYTES)
        return PublicKey(compressed_key)

    @classmethod
    def fromHex(self, _hex: str):
        return PublicKey(bytes.fromhex(_hex))

    def format(self):
        return "PublicKey{" + self.compressed_key.hex() + "}"
