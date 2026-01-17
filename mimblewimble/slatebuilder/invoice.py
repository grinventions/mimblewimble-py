import os
from uuid import UUID

from mimblewimble.consensus import Consensus
from mimblewimble.entity import OutputDataEntity
from mimblewimble.helpers.slate import calculateSigningKeys
from mimblewimble.models.transaction import EKernelFeatures, BlindingFactor
from mimblewimble.slatebuilder import ESlateStage, Slate, SlateSignature


class InvoiceSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed

    def build(
            self,
            amount: int,
            output: OutputDataEntity,
            block_height: int,
            slate_version=0):

        slate_id_bytes = os.urandom(16)
        slate_id = str(UUID(bytes=slate_id_bytes))

        stage = ESlateStage.INVOICE_SENT

        block_version = Consensus.getHeaderVersion(
            block_height)

        outputs = [output]
        inputs = []

        secret_key, public_key, secret_nonce, public_nonce = calculateSigningKeys(
            inputs=inputs,
            outputs=outputs,
            tx_offset=BlindingFactor.zero()
        )
        signature = SlateSignature(public_key, public_nonce)

        slate = Slate(
            slate_id,
            slate_version,
            block_version,
            amount,
            EKernelFeatures.DEFAULT_KERNEL,
            signatures=[signature],
            stage=stage)

        slate.appendOutput(
            output.getFeatures(),
            output.getCommitment(),
            output.getRangeProof())

        return slate, secret_key, secret_nonce