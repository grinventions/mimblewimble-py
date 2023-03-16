from typing import List, Tuple

from mimblewimble.entity import OutputDataEntity

from mimblewimble.helpers.fee import calculateFee


class SendSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed

    def build(
            self,
            amount: int,
            fee_base: int,
            changeOutputs: int,
            sendEntireBalance: bool,
            inputTotal: int,
            inputs: List[OutputDataEntity]
            recipients: List[str],
            slateVersion=0, strategy=0, addressOpt={}):
        numChangeOutputs = 0
        if not sendEntireBalance:
            numChangeOutputs = changeOutputs

        totalNumOutputs = 1 + numChangeOutputs
        numKernels = 1

        # calculate fee
        fee = calculateFee(fee_base, len(inputs), totalNumOutputs, numKernels)

        # amount to send
        amountToSend = amount
        if sendEntireBalance:
            amountToSend = inputTotal - fee

        # TODO create change outputs with total blinding factor xC

        # TODO select random transaction offset, and calculate secret key used in kernel signature

        # TODO payment proof

        # TODO add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
        pass

    def buildWalletTx(
            self,
            tx_offset: BlindingFactor,
            inputs: List[Nugget],
            change_outputs: List[Nugget],
            slate: Slate,
            address=None,
            proof=None):
        # TODO
        pass
