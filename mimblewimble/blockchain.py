import hashlib
import json  # TODO remove after debugging
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
        self.edgeBits = edgeBits  # 1 byte
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
        serializer.write(self.getEdgeBits().to_bytes(1, "big"))
        serializer.write(self.serializeCycle())

    def serializeCycle(self):
        bytes_len = int(((self.getEdgeBits() * Consensus.proofsize) + 7) / 8)
        serialized_bytes = bytearray(bytes_len)
        for n in range(len(self.getProofNonces())):
            for bit in range(int(self.getEdgeBits())):
                nonce = self.proofNonces[n]
                if nonce & (1 << bit) != 0:
                    positionTemp = (n * self.edgeBits) + bit
                    p = int(positionTemp / 8)
                    serialized_bytes[p] |= 1 << (positionTemp % 8)
        return serialized_bytes

    @classmethod
    def deserialize(self, B):
        edgeBits = int.from_bytes(B.read(1), "big")
        bytes_len = int(((edgeBits * Consensus.proofsize) + 7) / 8)
        bits = B.read(bytes_len)
        proofNonces = self.deserializeProofNonces(bits, edgeBits)
        return ProofOfWork(edgeBits, proofNonces)

    def deserializeProofNonces(bits, edgeBits):
        if edgeBits == 0 or edgeBits > 63:
            raise ValueError("Invalid number of edge bits {0}".format(str(edgeBits)))
        uint8_t1 = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        proofNonces = []
        for n in range(Consensus.proofsize):
            proofNonce = 0
            for bit in range(edgeBits):
                positionTemp = (n * edgeBits) + bit
                p = int(positionTemp / 8)
                if int(bits[p]) & (1 << (positionTemp % 8)):
                    proofNonce |= 1 << bit
            proofNonces.append(proofNonce)
        return proofNonces

    def getHash(self):
        cycle = self.serializeCycle()
        return hashlib.blake2b(cycle, digest_size=32).digest()


class BlockHeader:
    def __init__(
        self,
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
        proofOfWork,
    ):
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

    # pow

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
        serializer.write(self.version.to_bytes(2, "big"))
        serializer.write(self.height.to_bytes(8, "big"))
        serializer.write(self.timestamp.to_bytes(8, "big"))
        serializer.write(self.previousBlockHash)
        serializer.write(self.previousRoot)
        serializer.write(self.outputRoot)
        serializer.write(self.rangeProofRoot)
        serializer.write(self.kernelRoot)
        serializer.write(self.totalKernelOffset.serialize())  # blinding factor
        serializer.write(self.outputMMRSize.to_bytes(8, "big"))
        serializer.write(self.kernelMMRSize.to_bytes(8, "big"))
        serializer.write(self.totalDifficulty.to_bytes(8, "big"))
        serializer.write(self.scalingDifficulty.to_bytes(4, "big"))
        serializer.write(self.nonce.to_bytes(8, "big"))
        self.proofOfWork.serialize(serializer)

    @classmethod
    def deserialize(self, B: Serializer):
        version = int.from_bytes(B.read(2), "big")
        height = int.from_bytes(B.read(8), "big")
        timestamp = int.from_bytes(B.read(8), "big")
        previousBlockHash = B.read(32)
        previousRoot = B.read(32)
        outputRoot = B.read(32)
        rangeProofRoot = B.read(32)
        kernelRoot = B.read(32)

        totalKernelOffset = BlindingFactor.deserialize(B.read(32))

        outputMMRSize = int.from_bytes(B.read(8), "big")
        kernelMMRSize = int.from_bytes(B.read(8), "big")
        totalDifficulty = int.from_bytes(B.read(8), "big")
        scalingDifficulty = int.from_bytes(B.read(4), "big")
        nonce = int.from_bytes(B.read(8), "big")

        proofOfWork = ProofOfWork.deserialize(B)

        return BlockHeader(
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
            proofOfWork,
        )

    def toJSON(self):
        cuckooSolution = b""
        for proofNonce in self.getProofOfWork().getProofNonces():
            cuckooSolution += proofNonce.to_bytes(8, "big")

        return {
            "height": self.getHeight(),
            "hash": self.getHash().hex(),
            "version": self.getVersion(),
            "timestamp_raw": self.getTimestamp(),
            "timestamp_local": self.getTimestamp(),  # TODO convert to local
            "timestamp": self.getTimestamp(),  # TODO convert to UTC
            "previous": self.getPreviousHash().hex(),
            "prev_root": self.getPreviousRoot().hex(),
            "kernel_root": self.getKernelRoot().hex(),
            "output_root": self.getOutputRoot().hex(),
            "range_proof_root": self.getRangeProofRoot().hex(),
            "output_mmr_size": self.getOutputMMRSize(),
            "kernel_mmr_size": self.getKernelMMRSize(),
            "total_kernel_offset": self.getTotalKernelOffset().hex(),
            "secondary_scaling": self.getScalingDifficulty(),
            "total_difficulty": self.getTotalDifficulty(),
            "nonce": self.getNonce(),
            "edge_bits": self.getProofOfWork().getEdgeBits(),
            "cuckoo_solution": cuckooSolution.hex(),
        }

    @classmethod
    def fromDict(self, O: dict):
        return BlockHeader(
            O["version"],
            O["height"],
            O["timestamp"],
            O["previousBlockHash"],
            O["previousRoot"],
            O["rangeProofRoot"],
            O["kernelRoot"],
            O["totalKernelOffset"],
            O["outputMMRSize"],
            O["kernelMMRSize"],
            O["totalDifficulty"],
            O["scalingDifficulty"],
            O["nonce"],
            ProofOfWork.deserialize(O["proofOfWork"]),
        )

    @classmethod
    def fromJSON(self, jsonString: str):
        O = json.loads(jsonString)
        return BlockHeader.fromDict(O)

    def getPrePoW(self) -> bytes:
        """Return the pre-PoW serialised header bytes.

        This is the data that is hashed to produce the canonical block header
        hash used throughout Grin's protocol (locators, segment keys, etc.).
        The PoW nonce and cycle are excluded; the nonce field position is
        zeroed out before hashing.
        """
        s = Serializer()
        s.write(self.version.to_bytes(2, "big"))
        s.write(self.height.to_bytes(8, "big"))
        s.write(self.timestamp.to_bytes(8, "big"))
        s.write(self.previousBlockHash)
        s.write(self.previousRoot)
        s.write(self.outputRoot)
        s.write(self.rangeProofRoot)
        s.write(self.kernelRoot)
        s.write(self.totalKernelOffset.serialize())
        s.write(self.outputMMRSize.to_bytes(8, "big"))
        s.write(self.kernelMMRSize.to_bytes(8, "big"))
        s.write(self.totalDifficulty.to_bytes(8, "big"))
        s.write(self.scalingDifficulty.to_bytes(4, "big"))
        # nonce slot zeroed out (8 bytes) — excluded from hash pre-image
        s.write(b"\x00" * 8)
        return s.getvalue()

    # hashing

    def getHash(self) -> bytes:
        """Return the canonical blake2b-256 header hash.

        Computed over the pre-PoW serialised header bytes (nonce slot zeroed).
        This matches Grin's reference implementation:
          blake2b_256(pre_pow_bytes)
        NOT the PoW cycle hash — that is only used for the PoW proof itself.
        """
        return hashlib.blake2b(self.getPrePoW(), digest_size=32).digest()

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
            output_json["block_height"] = self.getHeight()
            outputs.append(output_json)

        return {
            "header": self.header.toJSON(),
            "inputs": [_input.toJSON() for _input in self.getInputs()],
            "outputs": outputs,
            "kernels": [kernel.toJSON() for kernel in self.getKernels()],
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
        self.short_ids = shortIds

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

    def serialize(self):
        # nonce is 8 bytes (uint64 big-endian)
        bytes_nonce = self.nonce.to_bytes(8, "big")

        bytes_num_outputs = len(self.getOutputs()).to_bytes(2, "big")
        bytes_num_kernels = len(self.getKernels()).to_bytes(2, "big")
        bytes_num_short_ids = len(self.getShortIds()).to_bytes(2, "big")

        outputs = self.getOutputs()
        bytes_outputs = b"".join(_output.serialize() for _output in outputs)

        kernels = self.getKernels()
        bytes_kernels = b"".join(_kernel.serialize() for _kernel in kernels)

        short_ids = self.getShortIds()
        bytes_short_ids = b"".join(_short_id.serialize() for _short_id in short_ids)

        return (
            bytes_nonce
            + bytes_num_outputs
            + bytes_num_kernels
            + bytes_num_short_ids
            + bytes_outputs
            + bytes_kernels
            + bytes_short_ids
        )

    @classmethod
    def deserialize(cls, B):
        """Deserialize a CompactBlock from a Serializer stream.

        Wire format: nonce(8) | num_outputs(2) | num_kernels(2) |
                     num_short_ids(2) | outputs | kernels | short_ids
        """
        header = BlockHeader.deserialize(B)
        nonce = int.from_bytes(B.read(8), "big")

        num_outputs = int.from_bytes(B.read(2), "big")
        num_kernels = int.from_bytes(B.read(2), "big")
        num_short_ids = int.from_bytes(B.read(2), "big")

        outputs = [TransactionOutput.deserialize(B) for _ in range(num_outputs)]
        kernels = [TransactionKernel.deserialize(B) for _ in range(num_kernels)]
        short_ids = [ShortId.deserialize(B) for _ in range(num_short_ids)]

        return CompactBlock(header, nonce, outputs, kernels, short_ids)

    def toJSON(self):
        outputs = []
        for _output in self.getOutputs():
            output_json = _output.toJSON()
            output_json["block_height"] = self.getHeight()
            outputs.append(output_json)

        return {
            "header": self.header.toJSON(),
            "nonce": self.nonce,
            "outputs": outputs,
            "kernels": [kernel.toJSON() for kernel in self.getKernels()],
            "short_ids": [sid.toJSON() for sid in self.getShortIds()],
        }

    # hashing
    def __hash__(self):
        return hash(self.header.getHash())

    def getHash(self):
        return self.header.getHash()
