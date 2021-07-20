import hashlib

from io import BytesIO
from enum import Enum

from mimblewimble.consensus import Consensus
from mimblewimble.commitment import Commitment
from mimblewimble.secret_key import SecretKey
from mimblewimble.rangeproof import RangeProof
from mimblewimble.fee import Fee
from mimblewimble.signature import Signature


class EProtocolVersion(Enum):
    V1 = 1
    V2 = 2
    V3 = 3
    V1000 = 1000


class EOutputFeatures(Enum):
    DEFAULT = 0
    COINBASE_OUTPUT = 1


class OutputFeatures:
    @classmethod
    def toString(self, features: EOutputFeatures):
        if features == EOutputFeatures.DEFAULT:
            return 'Plain'
        if features == EOutputFeatures.COINBASE_OUTPUT:
            return 'Coinbase'
        return ''

    @classmethod
    def fromString(self, string: str):
        if string == 'Plain':
            return EOutputFeatures.DEFAULT
        if string == 'Coinbase':
            return EOutputFeatures.COINBASE
        raise ValueError('Failed to deserialize output features: {0}'.format(string))


class EKernelFeatures(Enum):
    DEFAULT_KERNEL = 0
    COINBASE_KERNEL = 1
    HEIGHT_LOCKED = 2
    NO_RECENT_DUPLICATE = 3


class KernelFeatures:
    @classmethod
    def toString(self, features: EKernelFeatures):
        if features == EKernelFeatures.DEFAULT_KERNEL:
            return 'Plain'
        if features == EKernelFeatures.COINBASE_KERNEL:
            return 'Coinbase'
        if features == EKernelFeatures.HEIGHT_LOCKED:
            return 'HeightLocked'
        if features == EKernelFeatures.NO_RECENT_DUPLICATE:
            return 'NoRecentDuplicate'
        return ''

    @classmethod
    def fromString(self, string: str):
        if string == 'Plain':
            return EKernalFeatures.DEFAULT_KERNEL
        if string == 'Coinbase':
            return EKernalFeatures.COINBASE_KERNEL
        if string == 'HeightLocked':
            return EKernalFeatures.HEIGHT_LOCKED
        if string == 'NoRecentDuplicate':
            return EKernalFeatures.NO_RECENT_DUPLICATE
        raise ValueError('Failed to deserialize kernel features: {0}'.format(string))


class BlindingFactor:
    def __init__(self, blindingFactorBytes):
        self.blindingFactorBytes = blidningFactorBytes # 32 bytes

    def getBytes(self):
        return self.blindingFactorBytes

    def hex(self):
        return self.blindingFactorBytes.hex()

    def isNull(self):
        return all(v == b'\x00' for v in self.blindingFactorBytes)

    def serialize(self):
        return int(self.blindingFactorBytes)

    @classmethod
    def deserialize(self, blindingFactorInt: int):
        return BlindingFactor(blindingFactorInt.to_bytes(32, byteorder='big'))

    @classmethod
    def fromHex(self, hex: str):
        return BlindingFactor(bytes.fromHex(hex))

    def format(self):
        return 'BlindingFacotr{' + self.hex() + '}'

    def toSecretKey(self):
        return SecretKey(self.blindingFactorBytes)


class TransactionInput:
    def __init__(self, features: EOutputFeatures, commitment: Commitment):
        self.features = features
        self.commitment = commitment

    # operators

    def __lt__(self, other):
        return self.getCommitment() < other.getCommitment()

    def __eq__(self, other):
        return self.getFeatures() == other.getFeatures() and self.getCommitment() == other.getCommitment()

    # getters

    def getFeatures(self):
        return self.features

    def getCommitment(self):
        return self.commitment

    # serialization / deserialization

    def serialize(self, serializer, protocolVersion: EProtocolVersion):
        if protocolVersion == EProtocolVersion.V3:
            serializer.write(self.features.to_bytes(8))
        self.commitment.serialize(serializer)

    @classmethod
    def deserialize(self, byteBuffer: BytesIO, protocolVersion: EProtocolVersion):
        if protocolVersion == EProtocolVersion.V3:
            commitment = Commitment.deserialize(byteBuffer)
            features = EOutputFeatures(Global.getCoinView().getOutputType(commitment))
            return TransactionInput(features, commitment)
        else:
            features = EOutputFeatures(byteBuffer.read(1))
            commitment = Commitment.deserialize(byteBuffer)
            return TransactionInput(features, commitment)

    def toJSON(self):
        return {
            'features': str(self.getFeatures),
            'commit': self.getCommitment().toJSON()
        }

    @classmethod
    def fromJSON(self, transactionInputJSON):
        features = EOutputFeatures.fromString(transactionInputJSON['features'])
        commitment = Commitment(transactionInputJSON['commit'])
        return TransactionInput(features, commitment)

    # traits

    def __hash__(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return hashlib.blake2b(serialize.readall())


class TransactionOutput:
    def __init__(self, features: EOutputFeatures, commitment: Commitment, rangeProof: RangeProof):
        self.features = features
        self.commitment = commitment
        self.rangeProof = rangeProof

    # operators

    def __lt__(self, other):
        return self.getCommitment() < other.getCommitment()

    def __eq__(self, other):
        return hash(self) == hash(other)

    # getters

    def getFeatures(self):
        return self.features

    def getCommitment(self):
        return self.commitment

    def getRangeProof(self):
        return self.rangeProof

    def isCoinbase(self):
        return (self.features & EOutputFeatures.COINBASE_OUTPUT) == EOutputFeatures.COINBASE_OUTPUT

    # serialization/deserialization

    def serialize(self, serializer):
        serializer.write(self.features.to_bytes(8))
        self.commitment.serialize(serializer)
        self.rangeProof.serialize(serializer)

    @classmethod
    def deserialize(self, byteBuffer):
        features = EOutputFeatures(byteBuffer.read(1))
        commitment = Commitment.deserialize(byteBuffer)
        rangeProof = RangeProof.deserialize(byteBuffer)
        return TransactionInput(features, commitment, rangeProof)

    def toJSON(self):
        return {
            'features': str(self.getFeatures),
            'commit': self.getCommitment().toJSON(),
            'proof': self.getRangeProof().toJSON()
        }

    @classmethod
    def fromJSON(self, transactionOutputJSON):
        features = EOutputFeatures.fromString(transactionOutputJSON['features'])
        commitment = Commitment(transactionOutputJSON['commit'])
        rangeProof = RangeProof(transactionOutputJSON['proof'])
        return TransactionOutput(features, commitment, rangeProof)

    # traits

    def __hash__(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return hashlib.blake2b(serialize.readall())

    def format(self):
        return self.commitment.format()


class TransactionBody:
    def __init__(self, inputs, outputs, kernels):
        self.inputs = inputs
        self.outputs = outputs
        self.kernels = kernels

        self.inputs.sort()
        self.outputs.sort()
        self.kenrels.sort()

    def getInputs(self):
        return self.inputs

    def getInput(self, idx):
        assert idx < len(self.inputs)
        return self.inputs[idx]

    def getOutputs(self):
        return self.outputs

    def getOutput(self, idx):
        assert idx < len(self.outputs)
        return self.outputs[idx]

    def getKernels(self):
        return self.outputs

    def getKernel(self, idx):
        assert idx < len(self.kernels)
        return self.kernels[idx]

    def calcFee(self):
        smm = 0
        for kernel in self.getKernels():
            smm += kernel.getFee()
        return smm

    # TODO find default value of env or find how to handle env
    def calcWeight(self, block_height, env=None):
        num_inputs = len(self.getInputs())
        num_outptus = len(self.getOutputs())
        num_kernels = len(self.getKernels())

        if Consensus.getHeaderVersion(env, block_height) < 5:
            return Consensus.calculateWeightV4(num_inputs, num_outputs, num_kernels)
        else:
            return Consensus.calculateWeightV5(num_inputs, num_outputs, num_kernels)

    def getFeeShift(self):
        fee_shift = 0
        for kernel in self.getKenrels():
            if kernel.getFeeShift() > fee_shift:
                fee_shift = kernel.getFeeShift()
        return fee_shift


    def serialize(self):
        serializer = BytesIO()
        serializer.write(len(self.getInputs()).to_bytes(8))
        serializer.write(len(self.getOutputs()).to_bytes(8))
        serializer.write(len(self.getKernels()).to_bytes(8))

        # serialize inputs
        for input_ in self.getInputs():
            input_.serialize(serializer)

        # serialize outputs
        for output_ in self.getOutputs():
            outptu_.serialize(serializer)

        # serialize kernels
        for kernel_ in self.getKernels():
            kernel_.serialize(serializer)

        return serializer.readall()


    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        numInputs = byteBuffer.read(8)
        numOutputs = byteBuffer.read(8)
        numKernels = byteBuffer.read(8)

        # read inputs (variable size)
        inputs = []
        for i in range(numInputs):
            inputs.append(TransactionInput.deserialize(B))

        # read outputs (variable size)
        outputs = []
        for i in range(numOutputs):
            outputs.append(TransactionOutput.deserialize(B))

        # read kernels (variable size)
        kernels = []
        for i in range(numKernels):
            kernels.append(TransactionKernel.deserialize(B))

        inputs.sort()
        outouts.sort()
        kernels.sort()

        return TransactionBody(inputs, outputs, kernels)

    def toJSON(self):
        return {
            'inputs': [_input.toJSON() for _input in self.inputs],
            'outputs': [_outputs.toJSON() for _output in self.outputs],
            'kernels': [_kernel.toJSON() for _kernel in self.kernels]
        }

    @classmethod
    def fromJSON(self, transactionBodyJSON):
        inputs = []
        for _input in transactionBodyJSON.get('inputs', []):
            transaction_input = TransactionInput()
            transaction_input.fromJSON(_input)
            self.inputs.append(transaction_input)
        self.inputs.sort()

        outputs = []
        for _output in transactionBodyJSON.get('outputs', []):
            transaction_output = TransactionOutput()
            transaction_output.fromJSON(_output)
            self.outputs.append(transaction_output)
        self.outputs.sort()

        kernels = []
        for _kernel in transactionBodyJSON.get('kernels', []):
            transaction_kernel = TransactionKernel()
            transaction_kernel.fromJSON(_kernel)
            self.kernels.append(transaction_kernel)
        self.kernels.sort()

        return TransactionBody(inputs, outputs, kernels)


class TransactionKernel:
    def __init__(self, features: EKernelFeatures, fee: Fee, lockHeight: int, excessCommitment: Commitment, excessSignature: Signature):
        self.features = features
        self.fee = fee
        self.lockHeight = lockHeight
        self.excessCommitment = excessCommitment
        self.excessSignature = excessSignature

    # operators

    def __lt__(self, other):
        return self.getCommitment() < other.getCommitment()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return hash(self) == hash(other)

    # getters

    def getFeatures(self):
        return self.features

    def getFee(self):
        return self.fee

    def getFeeShift(self):
        return self.fee.getShift()

    def getLockHeight(self):
        return self.lockHeight

    def getCommitment(self):
        return self.getExcessCommitment()

    def getExcessCommitment(self):
        return self.excessCommitment

    def getExcessSignature(self):
        return self.excessSignature

    def isCoinbase(self):
        return (self.features & EOutputFeatures.COINBASE_OUTPUT) == EOutputFeatures.COINBASE_OUTPUT

    # serialization/deserialization

    # TODO handle the protocol version detection instead of argument
    def serialize(self, serializer, protocolVersion: EProtocolVersion):
        if protocolVersion >= EProtocolVersion.V2:
            serializer.write(self.features.to_bytes(8))
            if getFeatures() == EKernelFeatures.DEFAULT_KERNEL:
                self.fee.serialize(serializer)
            elif getFeatures() == EKernelFeatures.HEIGHT_LOCKED:
                self.fee.serialize(serializer)
                serializer.write(self.getLockHeight().to_bytes(8))
            elif getFeatures() == EKernelFeatures.NO_RECENT_DUPLICATE:
                self.fee.serialize(serializer)
                serializer.write(self.getLockHeight().to_bytes(2))
            self.excessCommitment.serialize(serializer)
            self.excessSignature.serialize(serializer)
        else:
            serializer.write(self.features.to_bytes(8))
            self.fee.serialize(serializer)
            serializer.write(self.getLockHeight().to_bytes(8))
            self.excessCommitment.serialize(serializer)
            self.excessSignature.serialize(serializer)


    # TODO handle the protocol version detection instead of argument
    def deserialize(self, byteBuffer: BytesIO, protocolVersion: EProtocolVersion):
        features = EKernelFeatures(serializer.read(1))
        fee = None
        lockHeight = 0
        if EProtocolVersion >= EProtocolVersion.V2:
            if features != EKernelKeatures.COINBASE_KERNEL:
                fee = Fee.deserialize(byteBuffer)

            if features == EKernelFeatures.HEIGHT_LOCKED:
                lockHeight = byteBuffer.read(8)
            elif features == EKernelFeatures.NO_RECENT_DUPLICATE:
                lockHeight = byteBuffer.read(2)
        else:
            fee = Fee.deserialize(byteBuffer)
            lockHeight = byteBuffer.read(8)

        # TODO make sure reads 33 bytes
        excessCommitment = Commitment.deserialize(byteBuffer)

        # TODO make sure reads 64 bytes
        excessSignature = Signature.deserialize(byteBuffer)

        if features == EKernelFeatures.NO_RECENT_DUPLICATE:
            if lockHeight == 0 or lockHeight > Consensus.WEEK_HEIGHT:
                raise ValueError('Invalid NRD relative height({0}) for kernel: {1}'.format(str(lockHeight), str(excessCommitment)))

        return TransactionKernel(features, fee, lockHeight, excessCommitment, excessSignature)

    def toJSON(self):
        features = {}
        if self.getFeatures() != EKernelFeatures.COINBASE_KERNEL:
            features['fee'] = self.fee.toJSON()
        if self.getFeatures() == EKernelFeatures.HEIGHT_LOCKED:
            features['lock_height'] = self.getLockHeight()
        return {
            'features': features,
            'excess': self.getExcessCommitment().toJSON(),
            'excess_sig': self.getExcessSignature().hex() # TODO find way to make it compact
        }

    @classmethod
    def fromJSON(self, transactionKernelJSON):
        features = KernelFeatures.fromString(transactionKernelJSON['features']) # TODO something fishy here... it should be a string, what is the exact json key?
        fee = Fee.fromJSON(transactionKernelJSON['features']['fee'])
        lockHeight = transactionKernelJSON['features']['lock_height']
        excessCommitment = Commitment.fromJSON(transactionKernelJSON['excess'])
        excessSignature = Signature.fromJSON(transactionKernelJSON['excess_sig']) # TODO find way to parse the compact signature
        if features == EKernelFeatures.NO_RECENT_DUPLICATE:
            if lockHeight == 0 or lockHeight > Consensus.WEEK_HEIGHT:
                raise ValueError('Invalid NRD relative height({0}) for kernel: {1}'.format(str(lockHeight), str(excessCommitment)))

        return TransactionKernel(features, fee, lockHeight, excessCommitment, excessSignature)

    # traits

    def __hash__(self):
        serializer = BytesIO()
        self.serialize(serializer)
        return hashlib.blake2b(serialize.readall())



class Transaction:
    def __init__(self, offset, body: TransactionBody):
        self.offset = offset # 32 bytes
        self.body = body # arbitrary size bytes

    def serialize(self):
        return self.offset + self.body

    def deserialize(self, byteString: bytes):
        # Read BlindingFactor/Offset (32 bytes)
        self.offset = byteString[0: 32]
        # Read Transaction Body (variable size)
        self.body = byteString[32:]

    def toJSON(self):
        return {
            'offset': self.offset.toJSON(),
            'body': self.body.toJSON()
        }


class TransactionPrivate:
    def __init__(self, amount, excess, recipient_address, recipient_signature, sender_address, sender_signature, slate_id):
        self.amount = amount # 8 bytes
        self.excess = excess # 33 bytes
        self.recipient_address = recipient_address # 32 bytes
        self.recipient_signature = recipient_signature # 64 bytes
        self.sender_address = sender_address # 32 bytes
        self.sender_signature = sender_signature # 64 bytes
        self.slate_id = slate_id
