from typing import Union

from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import EKernelFeatures

from mimblewimble.slatebuilder import SlatePaymentProof


class Slate:
    def __init__(
            self,
            version: int,
            block_version: int,
            amount: int,
            fee: int,
            proof_opt: Union[SlatePaymentProof, None],
            kernel_features: EKernelFeatures,
            transaction_offest: BlindingFactor,
            signatures=[]):
        self.version = version
        self.block_version = block_version
        self.amount = amount
        self.fee = fee
        self.proof_opt = proof_opt
        self.signatures = signatures
