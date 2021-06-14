class ProofOfWork:
    def __init__(self):
        # TODO
        pass

    def getEdgeBits(self):
        # TODO
        pass

    def getProofNonces(self):
        # TODO
        pass

    def isPrimary(self):
        # TODO
        pass

    def isSecondary(self):
        # TODO
        pass

    def getHash(self):
        # TODO
        pass


class BlockBody:
    def __init__(self):
        # TODO
        pass

    def getInputs(self):
        # TODO
        pass

    def getOutputs(self):
        # TODO
        pass

    def getKernels(self):
        # TODO
        pass

    def calcFee(self):
        # TODO
        pass


class BlockHeader:
    def __init__(self
                 version,
                 height,
                 timestamp,
                 previousBlockHash,
                 previousRoot,
                 outputRoot,
                 rangeProofRoot,
                 kernelRoot,
                 totalKernelOffset,
                 outputMMRSize,
                 kernelMMRSize,
                 totalDifficulty,
                 scalingDifficulty,
                 nonce,
                 proofOfWork):
        self.version = version
        self.height = height
        self.timestamp = timestamp
        self.previousBlockHash = previousBlockHash
        self.previousRoot = previousRoot
        self.outputRoot = outputRoot
        self.rangeProofRoot = rangeProofRoot
        self.kernelRoot = kernelRoot
        self.totalKernelOffset = totalKernelOffset
        self.outputMMRSize = ourputMMRSize
        self.kernelMMRSize = kernelMMRSize
        self.totalDifficulty = totalDifficulty
        self.scalingDifficulty = scalingDifficulty
        self.nonce = nonce
        self.proofOfWork = proofOfWork

    # getters

    def getVersion(self):
        return self.version

    def getHeight(self):
        return self.height

    def getPreviousHash(self):
        return self.previousBlockHash

    def getPreviousRoot(self):
        return self.previousRoot

    def getTimestamp(self):
        return self.timestamp

    def getTotalDifficulty(self):
        return self.totalDifficulty

    def getTotalScalingDifficulty(self):
        return self.scalingDifficulty

    def getTotalKernelOffset(self):
        return self.totalKernelOffset

    def getNonce(self):
        return self.nonce

    # PoW

    def getProofOfWork(self):
        return self.proofOfWork

    def getEdgeBits(self):
        return self.proofOfWork.getEdgeBits()

    def getProofNonces(self):
        return self.proofOfWork.getProofNonces()

    def isPrimaryPoW(self):
        return self.proofOfWork.isPrimary()

    def isSecondaryPoW(self):
        return self.proofOfWork.isSecondary()

    # Merklish root stuffz

    def getOutputRoot(self):
        return self.outputRoot

    def getRangeProofRoot(self):
        return self.rangeProofRoot

    def getKernelRoot(self):
        return self.kernelRoot

    # Merkle Mountain Range Sizes

    def getOutputMMRSize(self):
        return self.outputMMRSize

    def getKernelMMRSize(self):
        return self.kernelMMRSize

    # serialization / deserialization

    def serialize(self):
        # TODO
        pass

    def deserialize(self):
        # TODO
        pass

    def toJSON(self):
        # TODO
        pass

    def getPreProofOfWork(self):
        # TODO
        pass

    # hashing

    def getHash(self):
        return self.proofOfWork.getHash()

    def shortHash(self):
        # TODO
        pass


class FullBlock:
    def __init__(self, header, body, validated=False):
        self.header = header
        self.body = body
        self.validated = validated

    def getHeader(self):
        return self.header

    def getTransactionBody(self):
        return self.body

    def getInputs(self):
        return self.body.getInputs()

    def getOutputs(self):
        return self.body.getOutputs()

    def getKernels(self):
        return self.body.getKernels()

    def getInputCommitments(self):
        # TODO
        pass

    def getOutputCommitments(self):
        # TODO
        pass

    def getTotalFees(self):
        return self.body.calcFee()

    def calcWeight(self):
        return self.body.calcWeight(self.getHeight())

    def getHeight(self):
        return self.header.getHeight()

    def getPreviousHash(self):
        return self.header.getPreviousHash()

    def getTotalDifficulty(self):
        return self.header.getTotalDifficulty()

    def getTotalKernelOffset(self):
        return self.header.getTotalKernelOffset()

    def serialize(self):
        # TODO
        pass

    def deserialize(self):
        # TODO
        pass

    def toJSON(self):
        # TODO
        pass

    def getHash(self):
        # TODO
        pass

    def wasValidated(self):
        return self.validated

    def markAsValidated(self):
        self.validated = True
