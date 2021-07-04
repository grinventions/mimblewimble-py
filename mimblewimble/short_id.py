
class ShortId:
    def __init__(self, _id):
        self._id = _id

    # operators

    def __lt__(self, other):
        return self.getId() < other.getId()

    def __eq__(self, other):
        return self.getId() == other.getId()

    # getters

    def getId(self):
        return self._id

    # serialization / deserialization

    def serialize(self, serializer: BytesIO):
        serializer.write(self._id.to_bytes(6))

    @classmethod
    def deserializer(self, byteBuffer: BytesIO):
        return ShortId(int(byteBuffer.read(6)))

    # traits

    def __hash__(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return hashlib.blake2b(serialize.readall())
