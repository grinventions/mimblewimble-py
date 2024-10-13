import os

from typing import List, Tuple
from uuid import UUID

from mimblewimble.entity import OutputDataEntity

from mimblewimble.consensus import Consensus

from mimblewimble.crypto.secret_key import SecretKey

from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import EKernelFeatures
from mimblewimble.models.fee import Fee

from mimblewimble.helpers.slate import calculateSigningKeys

from mimblewimble.slatebuilder import ESlateStage
from mimblewimble.slatebuilder import Slate
from mimblewimble.slatebuilder import SlateSignature
from mimblewimble.slatebuilder import SlatePaymentProof


class SendSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed


    def build(
            self,
            amount: int,
            fee: int,
            block_height: int,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            slate_version=0, testnet=False,
            sender_address=None) -> Tuple[
                Slate, SecretKey, SecretKey]:
        # select random transaction offset,
        # and calculate secret key used in kernel signature
        transaction_offset = BlindingFactor.random()
        signing_keys = calculateSigningKeys(
            inputs, change_outputs, transaction_offset)
        secret_key, public_key, secret_nonce, public_nonce = signing_keys
        signature = SlateSignature(public_key, public_nonce)

        # payment proof
        payment_proof = SlatePaymentProof(sender_address, None)

        # add values to Slate for passing to other participants:
        # UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS

        slate_id_bytes = os.urandom(16)
        slate_id = str(UUID(bytes=slate_id_bytes))

        stage = ESlateStage.STANDARD_SENT

        block_version = Consensus.getHeaderVersion(block_height)
        slate = Slate(
            slate_id,
            slate_version,
            block_version,
            amount,
            Fee.fromInt(fee),
            payment_proof,
            EKernelFeatures.DEFAULT_KERNEL,
            transaction_offset,
            signatures=[signature],
            stage=stage)
        for inp in inputs:
            slate.appendInput(
                inp.getFeatures(),
                inp.getCommitment())
        for out in change_outputs:
            slate.appendOutput(
                out.getFeatures(),
                out.getCommitment(),
                out.getRangeProof())
        return slate, secret_key, secret_nonce


    def buildWalletTx(
            self,
            tx_offset: BlindingFactor,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            slate: Slate,
            receiver_address=None,
            payment_proof=None):
        if receiver_address is not None and isinstance(payment_proof, bytes):
            raise TypeError(
                'Expected bytes type argument or None for the receipient address')
        if payment_proof is not None and isinstance(payment_proof, SlatePaymentProof):
            raise TypeError('Expected SlatePaymentProof type argument or None')

        # TODO
        pass
