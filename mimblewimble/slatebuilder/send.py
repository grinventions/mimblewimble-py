import os

from typing import List, Tuple

from mimblewimble.entity import OutputDataEntity

from mimblewimble.models.transaction import BlindingFactor


class SendSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed

    def build(
            self,
            amount: int,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            recipients: List[str],
            slateVersion=0, strategy=0, addressOpt={}):
        # TODO select random transaction offset, and calculate secret key used in kernel signature
        transaction_offset = os.urandom(32)

        # TODO payment proof

        # TODO add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
        pass

    def buildWalletTx(
            self,
            tx_offset: BlindingFactor,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            slate,
            address=None,
            proof=None):
        # TODO
        pass
