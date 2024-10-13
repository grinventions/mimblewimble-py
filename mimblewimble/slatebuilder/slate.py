from enum import IntEnum
from typing import Union
from uuid import UUID

from mimblewimble.serializer import Serializer

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.pedersen import Pedersen
from mimblewimble.crypto.public_key import PublicKey
from mimblewimble.crypto.public_keys import PublicKeys
from mimblewimble.crypto.signature import Signature
from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.rangeproof import RangeProof

from mimblewimble.models.transaction import EOutputFeatures
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import EKernelFeatures
from mimblewimble.models.fee import Fee

from mimblewimble.slatebuilder import SlatePaymentProof


class ESlateStage(IntEnum):
    NONE = -1
    STANDARD_SENT = 1
    STANDARD_RECEIVED = 2
    STANDARD_FINALIZED = 3
    INVOICE_SENT = 4
    INVOICE_PAID = 5
    INVOICE_FINALIZED = 6


class SettableByte:
    def __init__(self, value: bytes):
        self.value = value

    def set_bit(self, index, x):
        mask = 1 << index
        self.value &= ~mask
        if x:
            self.value |= mask

    def get_bit(self, index):
        return (self.value >> index) & 1

    def get_value(self):
        return self.value

# 04   03   02   01    00
# ttl  feat fee  amt   num_parts
class OptionalFieldStatus:
    def __init__(
            self,
            include_num_parts: bool,
            include_amt: bool,
            include_fee: bool,
            include_feat: bool,
            include_ttl: bool):
        self.include_num_parts = include_num_parts
        self.include_amt = include_amt
        self.include_fee = include_fee
        self.include_feat = include_feat
        self.include_ttl = include_ttl

    def toByte(self):
        b = SettableByte(0x00)
        b.set_bit(0, self.include_num_parts)
        b.set_bit(1, self.include_amt)
        b.set_bit(2, self.include_fee)
        b.set_bit(3, self.include_feat)
        b.set_bit(4, self.include_ttl)
        return b.get_value()

    @classmethod
    def fromByte(self, value: bytes):
        b = SettableByte(value)
        include_num_parts = b.get_bit(0)
        include_amt = b.get_bit(1)
        include_fee = b.get_bit(2)
        include_feat = b.get_bit(3)
        include_ttl = b.get_bit(4)
        return OptionalFieldStatus(
            include_num_parts,
            include_amt,
            include_fee,
            include_feat,
            include_ttl)


# 01    00
# coms  proof
class OptionalStructStatus:
    def __init__(
            self,
            include_coms: bool,
            include_proof: bool):
        self.include_coms = include_coms
        self.include_proof = include_proof

    def toByte(self):
        b = SettableByte(0x00)
        b.set_bit(0, self.include_coms)
        b.set_bit(1, self.include_proof)
        return b.get_value()

    @classmethod
    def fromByte(self, value: bytes):
        b = SettableByte(value)
        include_coms = b.get_bit(0)
        include_proof = b.get_bit(1)
        return OptionalStructStatus(
            include_coms,
            include_proof)


class SlateSignature:
    def __init__(self, excess: PublicKey, nonce: PublicKey, signature=None, partial_opt=None):
        self.excess = excess
        self.nonce = nonce
        self.signature = signature
        self.partial_opt = partial_opt

    def getExcess(self):
        return self.excess

    def getNonce(self):
        return self.nonce

    def getSignature(self):
        return self.signature

    def setSignature(self, signature: Signature):
        self.signature = signature

    def serialize(self, serializer: Serializer):
        has_sig = 0
        if self.partial_opt is not None:
            has_sig = 1
        serializer.write(has_sig.to_bytes(1, 'big'))

        self.excess.serialize(serializer)
        self.nonce.serialize(serializer)

        if has_sig > 0:
            self.partial_opt.serialize_compressed(serializer)

    @classmethod
    def deserialize(self, serializer):
        has_sig = int.from_bytes(serializer.read(1), 'big')
        excess = PublicKey.deserialize(serializer)
        nonce = PublicKey.deserialize(serializer)
        partial_opt = None
        if has_sig > 0:
            partial_opt = Signature.deserialize_compressed(serializer)
        return SlateSignature(
            excess,
            nonce,
            partial_opt=partial_opt)

    def toJSON(self):
        obj = {}
        if self.excess is not None:
            obj['xs'] = self.excess.getBytes().hex()
        if self.nonce is not None:
            obj['nonce'] = self.nonce.getBytes().hex()
        if self.partial_opt is not None:
            obj['part'] = self.partial_opt.getSignatureBytes().hex()
        return obj


class SlateCommitment:
    def __init__(
            self,
            features: EOutputFeatures,
            commitment: Commitment,
            range_proof=None):
        self.features = features
        self.commitment = commitment
        self.range_proof = range_proof

    def setRangeProof(self, range_proof: RangeProof):
        self.range_proof = range_proof

    def serialize(self, serializer):
        has_proof = 0
        if self.range_proof is not None:
            has_proof = 1
        serializer.write(has_proof.to_bytes(1, 'big'))

        serializer.write(int(self.features).to_bytes(1, 'big'))
        self.commitment.serialize(serializer)

        if has_proof > 0:
            self.range_proof.serialize(serializer)

    @classmethod
    def deserialize(self, serializer):
        has_proof = int.from_bytes(serializer.read(1), 'big')
        features = EOutputFeatures(
            int.from_bytes(serializer.read(1), 'big'))
        commitment = Commitment.deserialize(serializer)

        range_proof = None
        if has_proof > 0:
            range_proof = RangeProof.deserialize(serializer)
        return SlateCommitment(
            features, commitment, range_proof=range_proof)

    def toJSON(self):
        obj = {}
        obj['c'] = self.commitment.hex()
        if self.features == EOutputFeatures.COINBASE_OUTPUT:
            obj['f'] = 1
        if self.range_proof is not None:
            obj['p'] = self.range_proof.getProofBytes().hex()
        return obj


class SlateFeatureArgs:
    def __init__(self, lock_height=None):
        self.lock_height = lock_height

    def getLockHeight(self):
        return self.lock_height

    def setLockHeight(self, lock_height: int):
        self.lock_height = lock_height

    def toJSON(self):
        obj = {}
        if self.lock_height is not None:
            obj['lock_hgt'] = self.lock_height
        return obj

    @classmethod
    def fromJSON(self, obj):
        return SlateFeatureArgs(lock_height=obj.get('lock_hgt', None))

class Slate:
    def __init__(
            self,
            slate_id: str,
            version: int,
            block_version: int,
            amount: int,
            fee: Fee,
            proof_opt: Union[SlatePaymentProof, None],
            kernel_features: EKernelFeatures,
            transaction_offest: BlindingFactor,
            signatures=[],
            commitments=[],
            lock_height=0,
            stage=ESlateStage.NONE,
            num_participants=2,
            ttl=0,
            kernel_features_args=None):
        self.slate_id = slate_id
        self.version = version
        self.block_version = block_version
        self.amount = amount
        self.fee = fee
        self.proof_opt = proof_opt
        self.kernel_features = kernel_features
        self.kernel_features_args = kernel_features_args,
        self.signatures = signatures
        self.stage = stage
        self.offset = transaction_offest
        self.lock_height = lock_height
        self.commitments = commitments
        self.num_participants = num_participants
        self.ttl = ttl


    def getAmount(self):
        return self.amount

    def getPaymentProof(self) -> Union[SlatePaymentProof, None]:
        return self.proof_opt


    def getSignature(self, i: int):
        if i < 0 or i > len(self.signatures):
            raise Exception('Signature index our of bounds')
        return self.signatures[i]

    def setSignature(self, i: int, signature: SlateSignature):
        if i < 0 or i > len(self.signatures):
            raise Exception('Signature index our of bounds')
        self.signatures[i] = signature


    def getKernelFeatures(self) -> EKernelFeatures:
        return self.kernel_features


    def getKernelCommitment(self) -> Commitment:
        p = Pedersen()
        kernel_commitment = p.toCommitment(
            self.calculateTotalExcess())
        del p
        return kernel_commitment


    def getFee(self):
        return self.fee


    def getLockHeight(self):
        return self.lock_height


    def setStage(self, stage: ESlateStage):
        self.stage = stage


    def appendSignature(self, signature: SlateSignature):
        self.signatures.append(signature)


    def appendInput(
            self,
            features: EOutputFeatures,
            commitment: Commitment):
        slate_commitment = SlateCommitment(features, commitment)
        self.commitments.append(slate_commitment)

    def appendOutput(
            self,
            features: EOutputFeatures,
            commitment: Commitment,
            range_proof: RangeProof):
        slate_commitment = SlateCommitment(features, commitment)
        slate_commitment.setRangeProof(range_proof)
        self.commitments.append(slate_commitment)


    def addOffset(self, offset: BlindingFactor):
        p = Pedersen()
        self.offset = p.blindSum([self.offset], [offset])
        del p


    def calculateTotalExcess(self):
        pks = PublicKeys()
        public_keys = []
        for signature in self.signatures:
            public_keys.append(signature.getExcess())
        summed = pks.publicKeySum(public_keys)
        del pks
        return summed


    def calculateTotalNonce(self):
        pks = PublicKeys()
        public_keys = []
        for signature in self.signatures:
            public_keys.append(signature.getNonce())
        summed = pks.publicKeySum(public_keys)
        del pks
        return summed

    def serialize(self) -> bytes:
        serializer = Serializer()

        serializer.write(self.version.to_bytes(2, 'big'))
        serializer.write(self.block_version.to_bytes(2, 'big'))

        slate_id = UUID('urn:uuid:{0}'.format(self.slate_id))
        serializer.write(slate_id.bytes)
        serializer.write(int(self.stage).to_bytes(1, 'big'))

        if self.offset is not None:
            serializer.write(self.offset.serialize())
        else:
            serializer.write(int(0).to_bytes(32, 'big'))

        include_num_parts = 0
        if self.num_participants != 2:
            include_num_parts = 1
        include_amt = 0
        if self.amount != 0:
            include_amt = 1
        include_fee = 0
        if self.fee is not None:
            include_fee = 1
        include_feat = 0
        if self.kernel_features != EKernelFeatures.DEFAULT_KERNEL:
            include_feat = 1
        include_ttl = 0
        if self.ttl != 0:
            include_ttl = 1
        field_status = OptionalFieldStatus(
            include_num_parts,
            include_amt,
            include_fee,
            include_feat,
            include_ttl)

        field_status_byte = field_status.toByte().to_bytes(1, 'big')
        serializer.write(field_status_byte)

        if include_num_parts:
            serializer.write(self.num_participants.to_bytes(1, 'big'))

        if include_amt:
            serializer.write(self.amount.to_bytes(8, 'big'))

        if include_fee:
            self.fee.serialize(serializer)

        if include_feat:
            serializer.write(int(self.kernel_features).to_bytes(1, 'big'))
            if self.kernel_features == EKernelFeatures.HEIGHT_LOCKED:
                lock_height = self.kernel_feauters.args.getLockHeight()
                serializer.write(lock_height.to_bytes(8, 'big'))

        if include_ttl:
            serializer.write(self.ttl.to_bytes(1, 'big'))

        num_sigs = len(self.signatures)
        serializer.write(num_sigs.to_bytes(1, 'big'))

        for signature in self.signatures:
            signature.serialize(serializer)

        include_coms = len(self.commitments) > 0
        include_proof = self.proof_opt is not None
        struct_status = OptionalStructStatus(include_coms, include_proof)
        struct_status_byte = struct_status.toByte().to_bytes(1, 'big')
        serializer.write(struct_status_byte)

        if include_coms:
            serializer.write(len(self.commitments).to_bytes(2, 'big'))
            for commitment in self.commitments:
                commitment.serialize(serializer)

        if include_proof:
            self.proof_opt.serialize(serializer)

        if self.kernel_features != EKernelFeatures.DEFAULT_KERNEL:
            if self.kernel_features == EKernelFeatures.HEIGHT_LOCKED:
                serializer.write(self.lock_height.to_bytes(8, 'big'))

        return serializer.readall()

    @classmethod
    def deserialize(self, value: bytes):
        serializer = Serializer()
        serializer.write(value)

        version = int.from_bytes(serializer.read(2), 'big')
        block_version = int.from_bytes(serializer.read(2), 'big')

        slate_id_bytes = serializer.read(16)
        slate_id = str(UUID(bytes=slate_id_bytes))

        stage_int = int.from_bytes(serializer.read(1), 'big')
        stage = ESlateStage(stage_int)

        transaction_offset_bytes = serializer.read(32)
        transaction_offset = None
        if int.from_bytes(transaction_offset_bytes, 'big') != 0:
            transaction_offset = BlindingFactor(transaction_offset_bytes)

        field_status_byte = int.from_bytes(serializer.read(1), 'big')
        field_status = OptionalFieldStatus.fromByte(field_status_byte)

        num_participants = 2
        if field_status.include_num_parts:
            num_participants = int.from_bytes(serializer.read(1), 'big')

        amount = 0
        if field_status.include_amt:
            amount = int.from_bytes(serializer.read(8), 'big')

        fee = None
        if field_status.include_fee:
            fee = Fee.deserialize(serializer)

        kernel_features = EKernelFeatures.DEFAULT_KERNEL
        kernel_features_args = None
        if field_status.include_feat:
            kernel_features = EKernelFeatures(int.from_bytes(serializer.read(1), 'big'))
            kernel_features_args = SlateFeatureArgs()
            if kernel_features == EKernelFeatures.HEIGHT_LOCKED:
                lock_height = int.from_bytes(serializer.read(8), 'big')
                kernel_features_args.setLockHeight(lock_height)

        ttl = 0
        if field_status.include_ttl:
            ttl = int.from_bytes(serializer.read(1), 'big')

        num_sigs = int.from_bytes(serializer.read(1), 'big')

        signatures = []
        for j in range(num_sigs):
            signatures.append(SlateSignature.deserialize(serializer))

        struct_status_byte = int.from_bytes(serializer.read(1), 'big')

        struct_status = OptionalStructStatus.fromByte(struct_status_byte)

        commitments = []
        if struct_status.include_coms:
            num_commitments = int.from_bytes(serializer.read(2), 'big')
            for j in range(num_commitments):
                commitments.append(SlateCommitment.deserialize(serializer))
                # where features is EOutputFeatures
                # use here slate.appendInput(features, commitment)

        proof_opt = None
        if struct_status.include_proof:
            proof_opt = SlatePaymentProof.deserialize(serializer)

        lock_height_opt = 0
        if kernel_features != EKernelFeatures.DEFAULT_KERNEL:
            if kernel_features == EKernelFeatures.HEIGHT_LOCKED:
                lock_height_opt = int.from_bytes(serializer.read(8), 'big')

        return Slate(
            slate_id,
            version,
            block_version,
            amount,
            fee,
            proof_opt,
            kernel_features,
            transaction_offset,
            signatures=signatures,
            commitments=commitments,
            lock_height=lock_height_opt,
            stage=stage,
            num_participants=num_participants,
            ttl=ttl,
            kernel_features_args=kernel_features_args)

    def toJSON(self):
        obj = {}
        obj['ver'] = '{0}:{1}'.format(
            str(self.version), str(self.block_version))
        obj['id'] = self.slate_id

        if self.stage == ESlateStage.STANDARD_SENT:
            obj['sta'] = 'S1'
        if self.stage == ESlateStage.STANDARD_RECEIVED:
            obj['sta'] = 'S2'
        if self.stage == ESlateStage.STANDARD_FINALIZED:
            obj['sta'] = 'S3'

        if self.offset is not None:
            obj['off'] = self.offset.hex()

        if self.num_participants != 2:
            obj['num_parts'] = self.num_participants

        if self.fee is not None:
            obj['fee'] = self.fee.toJSON()

        if self.amount != 0:
            obj['amt'] = self.amount

        if self.kernel_features != EKernelFeatures.DEFAULT_KERNEL:
            obj['feat'] = int(self.kernel_features)
            if self.kernel_features_args is not None:
                raise ValueError(
                    'Kernel feature arguments are None while kernel is not default')
            obj['feat_args'] = self.kernel_features_args.toJSON()

        if self.ttl != 0:
            obj['ttl'] = self.ttl

        if len(self.signatures) > 0:
            sigs = []
            for sig in self.signatures:
                sigs.append(sig.toJSON())
            obj['sigs'] = sigs

        coms = []
        for commitment in self.commitments:
            coms.append(commitment.toJSON())
        if len(coms) > 0:
            obj['coms'] = coms

        if self.proof_opt is not None:
            obj['proof'] = self.proof_opt.toJSON()

        return obj
