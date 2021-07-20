import hashlib
from io import BytesIO

from mimblewimble.consensus import Consensus
from mimblewimble.short_id import ShortId

from mimblewimble.transaction import TransactionInput
from mimblewimble.transaction import TransactionOutput
from mimblewimble.transaction import TransactionBody


class ProofOfWork:
    def __init__(self, edgeBits, proofNonces):
        self.edgeBits = edgeBits # 8 bytes
        self.proofNonces = proofNonces

    def getEdgeBits(self):
        return self.edgeBits

    def getProofNonces(self):
        return self.proofNonces

    def isPrimary(self):
        return Consensus.isPrimary(self.edgeBits)

    def isSecondary(self):
        return Consensus.isSecondary(self.edgeBits)

    def serialize(self):
        return self.getEdgeBits() + self.serializeCycle()

    def serializeCycle(self):
        bytes_len = ((self.getEdgeBits()*Consensus.proofsize)+7)/8
        serialized = b'0'*bytes_len
        uint64_t1 = b'0'*64 + 1
        uint8_t1 = b'0'*8 + 1
        for n in range(len(self.getProofNonces())):
            for bit in range(self.getEdgeBits()):
                nonce = self.proofNonces[n]
                if (nonce & (uint64_t1 << bit)) != 0:
                    positionTemp = (n*self.edgeBits)+bit
                    p = positionTemp/8
                    bits[p:p+8] = uint8_t1 << (positionTemp % 8)
        return bits

    def deserialize(self, byteString):
        B = BytesIO(byteString)
        edgeBits = B.read(1)
        bytes_len = ((edgeBits*Consensus.proofsize)+7)/8
        bits = B.read(bytes_len)
        proofNonces = self.deserializeProofNonces(bits, edgeBits)
        return ProofOfWork(edgeBits, proofNonces)

    def deserializeProofNonces(bits, edgeBits):
        if edgeBits == 0 or edgeBits > 63:
            raise ValueError('Invalid number of edge bits {0}'.format(str(edgeBits)))
        uint8_t1 = b'0'*8 + 1
        proofNonces = []
        for n in range(Consensus.proofsize):
            proofNonce = 0
            for bit in range(edgeBits):
                positionTemp = (n*edgeBits)+bit
                p = positionTemp/8
                if bits[p:p+8] & (uint8_t1 << (positionTemp % 8)) != 0:
                    proofNonce = uint8_t1 << bit
            proofNonces.append(proofNonce)
        return proofNonces

    def __hash__(self):
        return hashlib.blake2b(self.serializeCycle())

class BlockHeader:
    def __init__(self,
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
        self.outputMMRSize = outputMMRSize
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

    def getNumOutputs(self):
        # TODO implement the getLeafIndex
        pass

    def getNumKernels(self):
        # TODO implement the getLeafIndex
        pass

    # serialization / deserialization

    # 16+64*6+32*5=608 bytes
    def serialize(self):
        serializer = self.version.to_bytes(16)
        serializer += self.height.to_bytes(64)
        serializer += self.timestamp.to_bytes(64)
        serializer += self.previousBlockHash.to_bytes(32)
        serializer += self.previousRoot.to_bytes(32)
        serializer += self.rangeProofRoot.to_bytes(32)
        serializer += self.kernelRoot.to_bytes(32)
        totalKernelOffset = bytes(serializer)
        serializer = self.outputMMRSize.to_bytes(64)
        serializer += self.kernelMMRSize.to_bytes(64)
        serializer += self.totalDifficulty.to_bytes(64)
        serializer += self.scalingDifficulty.to_bytes(32)
        serializer += self.nonce.to_bytes(64)
        proofOfWork = bytes(serializer)
        return totalKernelOffset + proofOfWork

    @classmethod
    def deserialize(self, byteString: bytes):
        B = BytesIO(byteString)
        Btotal = BytesIO(byteString)

        version = int(B.read(2))
        height = int(B.read(8))
        timestamp = int(B.read(8))
        previousBlockHash = int(B.read(4))
        previousRoot = int(B.read(4))
        outputRoot = int(B.read(4))
        kernelRoot = int(B.read(4))

        totalKernelOffset = BlindingFactor.deserialize(Btotal.read(34))

        outputMMRSize = int(B.read(8))
        kernelMMRSize = int(B.read(8))
        totalDifficulty = int(B.read(8))
        scalingDifficulty = int(B.read(8))
        nonce = int(B.read(8))

        proofOfWork = ProofOfWork.deserialize(Btotal.read(40))

        return BlockHeader(version,
                           height,
                           timestamp,
                           previousBlockHash,
                           previousRoot,
                           rangeProofRoot,
                           kernelRoot,
                           totalKernelOffset,
                           outputMMRSize,
                           kernelMMRSize,
                           totalDifficulty,
                           scalingDifficulty,
                           nonce,
                           proofOfWork)


    def toJSON(self):
        cuckooSolution = b''
        for proofNonce in self.getProofOfWork().getProofNonces():
            cuckooSolution += proofNonce

        return {
            'height': self.getHeight(),
            'hash': self.__hash__().hex(),
            'version': self.getVersion(),
            'timestamp_raw': self.getTimestamp(),
            'timestamp_local': self.getTimestamp(), # TODO convert to local
            'timestamp': self.getTimeSTamp(), # TODO convert to UTC
            'previous': self.getPreviousHash().hex(),
            'prev_root': self.getPreviousRoot().hex(),
            'kernel_root': self.getKernelRoot().hex(),
            'output_root': self.getOutputRoot().hex(),
            'range_proof_root': self.getRangeProof().hex(),
            'output_mmr_size': self.getOutputMMRSize(),
            'kernel_mmr_size': self.getKernelMMRSize(),
            'total_kernel_offset': self.getTotalKernelOffset().serialize().hex(),
            'secondary_scaling': self.getScalingDifficulty(),
            'total_difficulty': self.getTotalDifficulty(),
            'nonce': self.getNonce(),
            'edge_bits': self.getProofOfWork().getEdgeBits(),
            'cuckoo_solution': cuckooSolution
        }

    @classmethod
    def fromJSON(jsonString: str):
        O = json.loads(jsonString)
        return BlockHeader(O['version'],
                           O['height'],
                           O['timestamp'],
                           O['previousBlockHash'],
                           O['previousRoot'],
                           O['rangeProofRoot'],
                           O['kernelRoot'],
                           O['totalKernelOffset'],
                           O['outputMMRSize'],
                           O['kernelMMRSize'],
                           O['totalDifficulty'],
                           O['scalingDifficulty'],
                           O['nonce'],
                           ProofOfWork.deserialize(O['proofOfWork']))

    def getPreProofOfWork(self):
        serializer = BytesIO()
        serializer.write(self.version.to_bytes(16))
        serializer.write(self.height.to_bytes(64))
        serializer.write(self.timestamp.to_bytes(64))
        serializer.write(self.previousBlockHash.to_bytes(32))
        serializer.write(self.previousRoot.to_bytes(32))
        serializer.write(self.outputRoot.to_bytes(32))
        serializer.write(self.rangeProofRoot.to_bytes(32))
        serializer.write(self.kernelRoot.to_bytes(32))
        totalKernelOffset = serializer.readall()

        serializer = BytesIO()
        serializer.write(self.outputMMRSize.to_bytes(64))
        serializer.write(self.kernelMMRSize.to_bytes(64))
        serializer.write(self.totalDifficulty.to_bytes(64))
        serializer.write(self.scalingDifficulty.to_bytes(32))
        serializer.write(self.nonce.to_bytes(64))
        proofOfWork = serializer.readall()

        return totalKernelOffset + proofOfWork

    # hashing

    def __hash__(self):
        return hash(self.proofOfWork)

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
        return [_input.getCommitment() for _input in self.getInputs()]

    def getOutputCommitments(self):
        return [_output.getCommitment() for _output in self.getOutputs()]

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
        # TODO check if it is just concatenation
        return self.header.serialize() + self.body.serialize()

    @classmethod
    def deserialize(self, byteBuffer):
        # TODO do not pass entire bytBuffer but adequate chunks
        header = BlockHeader.deserialize(byteBuffer)
        body = TransactionBody.deserialize(byteBuffer)
        return FullBlock(header, body)

    def toJSON(self):
        # transaction outputs
        outputs = []
        for _output in self.getOutputs():
            output_json = _output.toJSON()
            output_json['block_height'] = self.getHeight()
            outputs.append(output_json)

        return {
            'header': self.header.toJSON(),
            'inputs': [_input.toJSON() for _input in self.getInputs()],
            'outputs': outputs,
            'kernels': [kernel.toJSON() for kernel in self.getKernels()]
        }

    def __hash__(self):
        return hash(self.header)

    def wasValidated(self):
        return self.validated

    def markAsValidated(self):
        self.validated = True


class CompactBlock:
    def __init__(self, header, nonce, fullOutputs, fullKernels, shortIds):
        self.header = header
        self.nonce = nonce
        self.outputs = fullOutputs
        self.kernels = fullKernels
        self.short_ids = shoftIds

    # getters

    def getHeader(self):
        return self.header

    def getNonce(self):
        return self.nonce

    def getOutputs(self):
        return self.outputs

    def getKernels(self):
        return self.kernels

    def getShortIds(self):
        return self.short_ids

    def getPreviousHash(self):
        return self.header.getPreviousHash()

    def getHeight(self):
        return self.header.getHeight()

    def getTotalDifficulty(self):
        return self.header.getTotalDifficulty()

    # serialization / deserialization

    def serialize():
        # TODO check if there is a need to set byteorder='big'
        bytes_nonce = self.nonce.to_bytes(64)

        bytes_num_outputs = len(self.getOutputs()).to_bytes(64)
        bytes_num_kernels = len(self.getKernels()).to_bytes(64)
        bytes_num_short_ids = len(self.getShortIds()).to_bytes(64)

        outputs = self.getOutputs()
        bytes_outputs = outputs[0].serialize()
        for _output in outputs[1:]:
            bytes_outputs += _output.serialize()

        kernels = self.getKernels()
        bytes_kernels = kernels[0].serialize()
        for _kernel in kernels[1:]:
            bytes_kernels += _kernel.serialize()

        short_ids = self.getShortIds()
        bytes_short_ids = short_ids[0].serialize()
        for _short_id in short_ids[1:]:
            bytes_short_ids += _short_id.serialize()

        return bytes_nonce + bytes_num_otputs + bytes_num_kernels + bytes_num_short_ids + bytes_outputs + bytes_kernels + bytes_short_ids

    @classmethod
    def deserialize(byteString: bytes):
        nonce = int(byteString[0:64])

        numOutputs = int(byteString[65:128])
        numKernels = int(byteString[129:192])
        numShortIds = int(byteString[193:256])

        # TODO byteString should be shifted accordingly
        # TODO check how much it should be shifted at each iteration
        outputs = []
        for i in range(numOutputs):
            outputs.prepend(TransactionOutput.deserialize(byteString))

        kernels = []
        for i in range(numKernels):
            kernels.prepend(TransactionKernel.deserialize(byteString))

        shortIds = []
        for i in range(numShortIds):
            shortIds.prepend(ShortId.deserialize(byteString))

        return CompactBlock(nonce, outputs, kernels, shortIds)

    def toJSON():
        # transaction outputs
        outputs = []
        for _output in self.getOutputs():
            output_json = _output.toJSON()
            output_json['block_height'] = self.getHeight()
            outputs.append(output_json)

        return {
            'header': self.header.toJSON(),
            'inputs': [_input.toJSON() for _input in self.getInputs()],
            'outputs': outputs,
            'kernels': [kernel.toJSON() for kernel in self.getKernels()]
        }

    # hashing
    def __hash__():
        return hash(self.header)

