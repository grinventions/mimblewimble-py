from io import BytesIO


class Signature:
    def __init__(self, signatureBytes):
        self.signatureBytes = signatureBytes

    # operators

    def __eq__(self, other):
        return self.getSignatureBytes() == other.getSignatureBytes()

    # getters

    def getSignatureBytes(self):
        return self.signatureBytes

    # serialization / deserialization

    def serialize(self, serializer):
        for signature_byte in self.getSignatureBytes():
            serializer.write(signature_byte.to_bytes(1, 'big'))

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        return Signature(byteBuffer.read(8))

    def hex(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return serializer.read().hex()

    def format(self):
        return 'RawSig{' + self.hex() + '}'
