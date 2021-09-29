from io import BytesIO


class RangeProof:
    MAX_PROOF_SIZE = 675;

    def __init__(self, proofBytes: bytes):
        self.proofBytes = proofBytes

    # operators

    def __eq__(self, other):
        return self.getProofBytes() == other.getProofBytes()

    # getters

    def getProofBytes(self):
        return self.proofBytes

    # serialization / deserialization

    def serialize(self, serializer):
        serializer.write((len(self.getProofBytes())).to_bytes(8, 'big'))
        for proof_bytes in self.getProofBytes():
            serializer.write(proof_bytes.to_bytes(1, 'big'))

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        proofSize = byteBuffer.readall()
        if len(proofSize) > MAX_PROOF_SIZE:
            raise ValueError('Proof of size {0} exceeds the maximum'.format(str(len(proofSize))))
        return RangeProof(proofSize)

    def hex(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return serializer.read().hex()

    def toJSON(self):
        return self.hex()

    @classmethod
    def fromhex(self, _hex: str):
        return RangeProof(bytes.fromhex(_hex))

    def format(self):
        return self.hex()
