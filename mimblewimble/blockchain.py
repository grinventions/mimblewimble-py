import hashlib
import json # TODO remove after debugging
from io import BytesIO

from mimblewimble.mmr.index import MMRIndex
from mimblewimble.serializer import Serializer

from mimblewimble.consensus import Consensus
from mimblewimble.models.short_id import ShortId

from mimblewimble.models.transaction import TransactionInput
from mimblewimble.models.transaction import TransactionOutput
from mimblewimble.models.transaction import TransactionBody
from mimblewimble.models.transaction import BlindingFactor


class ProofOfWork:
    def __init__(self, edgeBits, proofNonces):
        self.edgeBits = edgeBits # 1 byte
        self.proofNonces = proofNonces

    def getEdgeBits(self):
        return self.edgeBits

    def getProofNonces(self):
        return self.proofNonces

    def isPrimary(self):
        return Consensus.isPrimary(self.edgeBits)

    def isSecondary(self):
        return Consensus.isSecondary(self.edgeBits)

    def serialize(self, serializer):
        serializer.write(self.getEdgeBits().to_bytes(1, 'big'))
        serializer.write(self.serializeCycle())

    def serializeCycle(self):
        bytes_len = int(((self.getEdgeBits()*Consensus.proofsize)+7)/8)
        serialized_bytes = bytearray(bytes_len)
        for n in range(len(self.getProofNonces())):
            for bit in range(int(self.getEdgeBits())):
                nonce = self.proofNonces[n]
                if nonce & (1 << bit) != 0:
                    positionTemp = (n*self.edgeBits)+bit
                    p = int(positionTemp/8)
                    serialized_bytes[p] |= (1 << (positionTemp % 8))
        return serialized_bytes

    @classmethod
    def deserialize(self, B):
        edgeBits = int.from_bytes(B.read(1), 'big')
        bytes_len = int(((edgeBits*Consensus.proofsize)+7)/8)
        bits = B.read(bytes_len)
        proofNonces = self.deserializeProofNonces(bits, edgeBits)
        return ProofOfWork(edgeBits, proofNonces)

    def deserializeProofNonces(bits, edgeBits):
        if edgeBits == 0 or edgeBits > 63:
            raise ValueError('Invalid number of edge bits {0}'.format(str(edgeBits)))
        uint8_t1 = b'\x00\x00\x00\x00\x00\x00\x00\x01'
        proofNonces = []
        for n in range(Consensus.proofsize):
            proofNonce = 0
            for bit in range(edgeBits):
                positionTemp = (n*edgeBits)+bit
                p = int(positionTemp/8)
                if int(bits[p]) & (1 << (positionTemp % 8)):
                    proofNonce |= 1 << bit
            proofNonces.append(proofNonce)
        return proofNonces

    def getHash(self):
        cycle = self.serializeCycle()
        return hashlib.blake2b(cycle, digest_size=32).digest()


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

    def getScalingDifficulty(self):
        return self.scalingDifficulty

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
        return MMRIndex.at(self.outputMMRSize).getLeafIndex()

    def getNumKernels(self):
        return MMRIndex.at(self.kernelMMRSize).getLeafIndex()

    # serialization / deserialization

    def serialize(self, serializer: Serializer):
        serializer.write(self.version.to_bytes(2, 'big'))
        serializer.write(self.height.to_bytes(8, 'big'))
        serializer.write(self.timestamp.to_bytes(8, 'big'))
        serializer.write(self.previousBlockHash)
        serializer.write(self.previousRoot)
        serializer.write(self.outputRoot)
        serializer.write(self.rangeProofRoot)
        serializer.write(self.kernelRoot)
        serializer.write(self.totalKernelOffset.serialize()) # blinding factor
        serializer.write(self.outputMMRSize.to_bytes(8, 'big'))
        serializer.write(self.kernelMMRSize.to_bytes(8, 'big'))
        serializer.write(self.totalDifficulty.to_bytes(8, 'big'))
        serializer.write(self.scalingDifficulty.to_bytes(4, 'big'))
        serializer.write(self.nonce.to_bytes(8, 'big'))
        self.proofOfWork.serialize(serializer)

    @classmethod
    def deserialize(self, B: Serializer):
        version = int.from_bytes(B.read(2), 'big')
        height = int.from_bytes(B.read(8), 'big')
        timestamp = int.from_bytes(B.read(8), 'big')
        previousBlockHash = B.read(32)
        previousRoot = B.read(32)
        outputRoot = B.read(32)
        rangeProofRoot = B.read(32)
        kernelRoot = B.read(32)

        totalKernelOffset = BlindingFactor.deserialize(B.read(32))

        outputMMRSize = int.from_bytes(B.read(8), 'big')
        kernelMMRSize = int.from_bytes(B.read(8), 'big')
        totalDifficulty = int.from_bytes(B.read(8), 'big')
        scalingDifficulty = int.from_bytes(B.read(4), 'big')
        nonce = int.from_bytes(B.read(8), 'big')

        proofOfWork = ProofOfWork.deserialize(B)

        return BlockHeader(version,
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
                           proofOfWork)


    def toJSON(self):
        cuckooSolution = b''
        for proofNonce in self.getProofOfWork().getProofNonces():
            cuckooSolution += proofNonce.to_bytes(8, 'big')

        return {
            'height': self.getHeight(),
            'hash': self.getHash().hex(),
            'version': self.getVersion(),
            'timestamp_raw': self.getTimestamp(),
            'timestamp_local': self.getTimestamp(), # TODO convert to local
            'timestamp': self.getTimestamp(), # TODO convert to UTC
            'previous': self.getPreviousHash().hex(),
            'prev_root': self.getPreviousRoot().hex(),
            'kernel_root': self.getKernelRoot().hex(),
            'output_root': self.getOutputRoot().hex(),
            'range_proof_root': self.getRangeProofRoot().hex(),
            'output_mmr_size': self.getOutputMMRSize(),
            'kernel_mmr_size': self.getKernelMMRSize(),
            'total_kernel_offset': self.getTotalKernelOffset().hex(),
            'secondary_scaling': self.getScalingDifficulty(),
            'total_difficulty': self.getTotalDifficulty(),
            'nonce': self.getNonce(),
            'edge_bits': self.getProofOfWork().getEdgeBits(),
            'cuckoo_solution': cuckooSolution.hex()
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

    def getPreProofOfWork(self, serializer):
        serializer = BytesIO()
        self.serialize(serializer)
        return serializer.getvalue()

    # hashing

    def getHash(self):
        return self.proofOfWork.getHash()

    def shortHash(self):
        # TODO
        pass


class FullBlock:
    def __init__(self, header: BlockHeader, body: TransactionBody, validated=False):
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
        serializer = Serializer()
        self.header.serialize(serializer)
        self.body.serialize(serializer)
        return serializer.getvalue()

    @classmethod
    def deserialize(self, serializer: Serializer):
        header = BlockHeader.deserialize(serializer)
        body = TransactionBody.deserialize(serializer)
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

    def getHash(self):
        return self.header.getHash()

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

