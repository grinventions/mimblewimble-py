from io import BytesIO

from mimblewimble.serializer import Serializer


class Signature:
    def __init__(self, signatureBytes, compact=False):
        self.signatureBytes = signatureBytes
        self.compact = compact

    # operators

    def __eq__(self, other):
        return self.getSignatureBytes() == other.getSignatureBytes()

    # getters

    def isCompact(self):
        return self.compact

    def getSignatureBytes(self):
        return self.signatureBytes

    # serialization / deserialization

    def serialize(self, serializer: Serializer):
        assert len(self.getSignatureBytes()) == 64
        for signature_byte in self.getSignatureBytes():
            serializer.write(signature_byte.to_bytes(1, "big"))

    @classmethod
    def deserialize(self, serializer: Serializer):
        signature_bytes = serializer.read(64)
        return Signature(signature_bytes)

    def serialize_compressed(self, serializer: Serializer):
        signature_bytes = self.getSignatureBytes()
        assert len(signature_bytes) == 64
        r = signature_bytes[0:32]
        r = bytearray(r)
        r.reverse()
        r = bytes(r)

        s = signature_bytes[32:64]
        s = bytearray(s)
        s.reverse()
        s = bytes(s)

        serializer.write(r)
        serializer.write(s)

    @classmethod
    def deserialize_compressed(self, serializer: Serializer):
        r = serializer.read(32)
        r = bytearray(r)
        r.reverse()
        r = bytes(r)

        s = serializer.read(32)
        s = bytearray(s)
        s.reverse()
        s = bytes(s)

        signature_bytes = r + s
        return Signature(signature_bytes, compact=True)

    def hex(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return serializer.read().hex()

    def format(self):
        return "RawSig{" + self.hex() + "}"
