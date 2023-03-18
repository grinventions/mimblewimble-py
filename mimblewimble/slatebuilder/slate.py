from enum import IntEnum
from typing import Union

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
    STANDARD_SENT = 2
    STANDARD_RECEIVED = 3
    STANDARD_FINALIZED = 4
    INVOICE_SENT = 5
    INVOICE_PAID = 6
    INVOICE_FINALIZED = 7


class SlateSignature:
    def __init__(self, excess: PublicKey, nonce: PublicKey, signature=None):
        self.excess = excess
        self.nonce = nonce
        self.signature = signature

    def getExcess(self):
        return self.excess

    def getNonce(self):
        return self.nonce

    def getSignature(self):
        return self.signature

    def setSignature(self, signature: Signature):
        self.signature = signature

    def toJSON(self):
        obj = {}
        if self.excess is not None:
            obj['xs'] = self.excess.getBytes().hex()
        if self.nonce is not None:
            obj['nonce'] = self.nonce.getBytes().hex()
        if self.signature is not None:
            obj['part'] = self.signature.hex()
        return obj


class SlateCommitment:
    def __init__(
            self,
            features: EOutputFeatures,
            commitment: Commitment):
        self.features = features
        self.commitment = commitment
        self.range_proof = None

    def setRangeProof(self, range_proof: RangeProof):
        self.range_proof = range_proof

    def toJSON(self):
        obj = {}
        obj['c'] = self.commitment.hex()
        if self.features == EOutputFeatures.COINBASE_OUTPUT:
            obj['f'] = 1
        if self.range_proof is not None:
            obj['p'] = self.range_proof.hex()
        return obj


class Slate:
    def __init__(
            self,
            version: int,
            block_version: int,
            amount: int,
            fee: Fee,
            proof_opt: Union[SlatePaymentProof, None],
            kernel_features: EKernelFeatures,
            transaction_offest: BlindingFactor,
            signatures=[],
            lock_height=0):
        self.version = version
        self.block_version = block_version
        self.amount = amount
        self.fee = fee
        self.proof_opt = proof_opt
        self.kernel_features = kernel_features
        self.signatures = signatures
        self.stage = ESlateStage.NONE
        self.offset = transaction_offest
        self.lock_height = lock_height
        self.commitments = []


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

    def toJSON(self):
        obj = {}
        obj['amt'] = self.amount

        if self.stage == ESlateStage.STANDARD_SENT:
            obj['sta'] = 'S1'
        if self.stage == ESlateStage.STANDARD_RECEIVED:
            obj['sta'] = 'S2'
        if self.stage == ESlateStage.STANDARD_FINALIZED:
            obj['sta'] = 'S3'

        if self.offset is not None:
            obj['off'] = self.offset.hex()

        if self.fee is not None:
            obj['fee'] = self.fee.toJSON()

        if len(self.signatures) > 0:
            sigs = []
            for sig in self.signatures:
                sigs.append(sig.toJSON())

        coms = []
        for commitment in self.commitments:
            coms.append(commitment.toJSON())
        obj['coms'] = coms

        if self.proof_opt is not None:
            obj['proof'] = self.proof_opt.toJSON()

        return obj
