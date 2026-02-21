from typing import List, Tuple

from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.entity import OutputDataEntity
from mimblewimble.helpers.slate import calculateSigningKeys
from mimblewimble.models.fee import Fee
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.slatebuilder import Slate, SlateSignature, ESlateStage


class PaySlateBuilder:
    def __init__(self, master_seed):
        self.master_seed = master_seed

    def build(
        self,
        invoice_slate: Slate,
        fee: int,
        inputs: List[OutputDataEntity],
        change_outputs: List[OutputDataEntity],
    ) -> Tuple[Slate, SecretKey, SecretKey]:
        # select random transaction offset,
        # and calculate secret key used in kernel signature
        transaction_offset = BlindingFactor.random()
        signing_keys = calculateSigningKeys(inputs, change_outputs, transaction_offset)
        secret_key, public_key, secret_nonce, public_nonce = signing_keys
        signature = SlateSignature(public_key, public_nonce)

        invoice_slate.fee = Fee.fromInt(fee)

        for inp in inputs:
            invoice_slate.appendInput(inp.getFeatures(), inp.getCommitment())
        for out in change_outputs:
            invoice_slate.appendOutput(
                out.getFeatures(), out.getCommitment(), out.getRangeProof()
            )

        invoice_slate.setStage(ESlateStage.INVOICE_PAID)
        invoice_slate.addSignature(signature)

        return invoice_slate, secret_key, secret_nonce
