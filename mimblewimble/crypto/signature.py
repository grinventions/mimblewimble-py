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
            serializer.write(signature_byte.to_bytes(1, 'big'))

    @classmethod
    def deserialize(self, serializer: Serializer):
        return Signature(serializer.read(64))

    def hex(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return serializer.read().hex()

    def format(self):
        return 'RawSig{' + self.hex() + '}'
