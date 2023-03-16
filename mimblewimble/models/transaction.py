import hashlib

from io import BytesIO
from enum import IntEnum

from mimblewimble.consensus import Consensus
from mimblewimble.serializer import Serializer, EProtocolVersion
from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.signature import Signature
from mimblewimble.crypto.rangeproof import RangeProof
from mimblewimble.models.fee import Fee


class EOutputStatus(IntEnum):
    SPENDABLE = 0
    IMMATURE = 1 # DEPRECATED: Outputs should be marked as spendable.
    NO_CONFIRMATIONS = 2
    SPENT = 3
    LOCKED = 4
    CANCELED = 5


class EOutputFeatures(IntEnum):
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


class EKernelFeatures(IntEnum):
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
        self.blindingFactorBytes = blindingFactorBytes # 32 bytes

    def getBytes(self):
        return self.blindingFactorBytes

    def hex(self):
        return self.blindingFactorBytes.hex()

    def isNull(self):
        return all(v == b'\x00' for v in self.blindingFactorBytes)

    def serialize(self):
        return self.blindingFactorBytes

    @classmethod
    def deserialize(self, blindingFactorBytes):
        return BlindingFactor(blindingFactorBytes)

    @classmethod
    def fromHex(self, hex: str):
        return BlindingFactor(bytes.fromHex(hex))

    def format(self):
        return 'BlindingFactor{' + self.hex() + '}'

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

    def serialize(self, serializer):
        if serializer.getProtocol().value == EProtocolVersion.V3.value:
            serializer.write(self.features.to_bytes(1))
        self.commitment.serialize(serializer)

    @classmethod
    def deserialize(self, byteBuffer: BytesIO):
        if serializer.getProtocol().value == EProtocolVersion.V3.value:
            commitment = Commitment.deserialize(byteBuffer)
            features = EOutputFeatures(Global.getCoinView().getOutputType(commitment))
            return TransactionInput(features, commitment)
        else:
            features = EOutputFeatures(byteBuffer.read(1))
            commitment = Commitment.deserialize(byteBuffer)
            return TransactionInput(features, commitment)

    def toJSON(self):
        return {
            'features': self.getFeatures().value,
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
        return hashlib.blake2b(serialize.getvalue())


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

    def serialize(self, serializer: Serializer):
        serializer.write(self.features.value.to_bytes(1, 'big'))
        self.commitment.serialize(serializer)
        self.rangeProof.serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        features = EOutputFeatures(int.from_bytes(serializer.read(1), 'big'))
        commitment = Commitment.deserialize(serializer)
        rangeProof = RangeProof.deserialize(serializer)
        return TransactionOutput(features, commitment, rangeProof)

    def toJSON(self):
        return {
            'features': self.getFeatures().value,
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
        self.kernels.sort()

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
        return self.kernels

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


    def serialize(self, serializer):
        serializer.write(len(self.getInputs()).to_bytes(8, 'big'))
        serializer.write(len(self.getOutputs()).to_bytes(8, 'big'))
        serializer.write(len(self.getKernels()).to_bytes(8, 'big'))

        # serialize inputs
        for input_ in self.getInputs():
            input_.serialize(serializer)

        # serialize outputs
        for output_ in self.getOutputs():
            output_.serialize(serializer)

        # serialize kernels
        for kernel_ in self.getKernels():
            kernel_.serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        numInputs = int.from_bytes(serializer.read(8), 'big')
        numOutputs = int.from_bytes(serializer.read(8), 'big')
        numKernels = int.from_bytes(serializer.read(8), 'big')

        # read inputs (variable size)
        inputs = []
        for i in range(numInputs):
            inputs.append(TransactionInput.deserialize(serializer))

        # read outputs (variable size)
        outputs = []
        for i in range(numOutputs):
            outputs.append(TransactionOutput.deserialize(serializer))

        # read kernels (variable size)
        kernels = []
        for i in range(numKernels):
            kernels.append(TransactionKernel.deserialize(serializer))

        inputs.sort()
        outputs.sort()
        kernels.sort()

        return TransactionBody(inputs, outputs, kernels)

    def toJSON(self):
        return {
            'inputs': [_input.toJSON() for _input in self.inputs],
            'outputs': [_output.toJSON() for _output in self.outputs],
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
    def serialize(self, serializer: Serializer):
        if serializer.getProtocol().value >= EProtocolVersion.V2.value:
            serializer.write(self.features.value.to_bytes(1, 'big'))
            if self.getFeatures() == EKernelFeatures.DEFAULT_KERNEL:
                self.fee.serialize(serializer)
            elif self.getFeatures() == EKernelFeatures.HEIGHT_LOCKED:
                self.fee.serialize(serializer)
                serializer.write(self.getLockHeight().to_bytes(8, 'big'))
            elif self.getFeatures() == EKernelFeatures.NO_RECENT_DUPLICATE:
                self.fee.serialize(serializer)
                serializer.write(self.getLockHeight().to_bytes(2, 'big'))
        else:
            serializer.write(self.features.value.to_bytes(1, 'big'))
            self.fee.serialize(serializer)
            serializer.write(self.getLockHeight().to_bytes(8, 'big'))
        self.getExcessCommitment().serialize(serializer)
        self.getExcessSignature().serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        features = EKernelFeatures(int.from_bytes(serializer.read(1), 'big'))
        fee = None
        lockHeight = 0
        if serializer.getProtocol().value >= EProtocolVersion.V2.value:
            if features != EKernelKeatures.COINBASE_KERNEL.value:
                fee = Fee.deserialize(serializer)

            if features.value == EKernelFeatures.HEIGHT_LOCKED.value:
                lockHeight = int.from_bytes(serializer.read(8), 'big')
            elif features.value == EKernelFeatures.NO_RECENT_DUPLICATE.value:
                lockHeight = int.from_bytes(serializer.read(2), 'big')
        else:
            fee = Fee.deserialize(serializer)
            lockHeight = int.from_bytes(serializer.read(8), 'big')

        excessCommitment = Commitment.deserialize(serializer)
        excessSignature = Signature.deserialize(serializer)

        if features.value == EKernelFeatures.NO_RECENT_DUPLICATE.value:
            if lockHeight == 0 or lockHeight > Consensus.WEEK_HEIGHT.value:
                raise ValueError('Invalid NRD relative height({0}) for kernel: {1}'.format(str(lockHeight), str(excessCommitment)))

        return TransactionKernel(features, fee, lockHeight, excessCommitment, excessSignature)

    def toJSON(self):
        features = {}
        if self.getFeatures() != EKernelFeatures.COINBASE_KERNEL.value:
            features['fee'] = self.fee.toJSON()
        if self.getFeatures() == EKernelFeatures.HEIGHT_LOCKED.value:
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
