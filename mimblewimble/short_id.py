import hashlib

from io import BytesIO
from siphash import siphash_64


class ShortId:
    def __init__(self, _id):
        self._id = _id

    @classmethod
    def create(self, _hash: bytes, _blockHash: bytes, nonce: int):
        serializer = BytesIO()
        serializer.write(_blockHash)
        serializer.write(nonce.to_bytes(8, byteorder='big'))
        serialized = serializer.getvalue()
        _hashWithNonce = hashlib.blake2b(serialized, digest_size=32).digest()

        # extract k0/k1 from the block hash
        byteBuffer = BytesIO(_hashWithNonce)
        k0 = bytearray(byteBuffer.read(8))
        k0 = bytes(k0)
        k0 = int.from_bytes(k0, byteorder='little')
        k1 = bytearray(byteBuffer.read(8))
        k1 = int.from_bytes(k1, byteorder='little')
        key = k0.to_bytes(8, byteorder='little') + k1.to_bytes(8, byteorder='little')
        # SipHash24 our hash using the k0 and k1 keys
        sipHash = siphash_64(key, _hash)

        # construct short_id from the resulting bytes (dropping 2 most significant bytes)
        _id = int.from_bytes(sipHash[:-2], byteorder='little')
        return ShortId(_id)


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
        return hashlib.blake2b(serializer.read()).digest()
