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
        serializer.write(self.getProofBytes())

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        proofSize = byteBuffer.readall()
        if len(proofSize) > MAX_PROOF_SIZE:
            raise ValueError('Proof of size {0} exceeds the maximum'.format(str(len(proofSize))))
        return RangeProof(proofSize)

    def hex(self):
        return self.getProofBytes().hex()

    @classmethod
    def fromhex(self, _hex: str):
        return RangeProof(bytes.fromhex(_hex))

    def format(self):
        return self.hex()
