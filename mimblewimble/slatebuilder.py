from typing import List

from mimblewimble.models.transaction import BlindingFactor


class Slate:
    def __init__(self):
        pass


class SlatePaymentProof:
    def __init__(self):
        pass


# Nugget dictionary definition: A small, solid lump, especially of gold.
# In GrinPlusPlus this type is called OutputDataEntity
# I call it Nugget because I don't want to call it output if it
# can also be an input
class Nugget:
    def __init__(self):
        pass


class SendSlateBuilder:
    def __init__(self, masterSeed):
        pass


    def buildSendSlate(
            self, amount: int, feeBase: int,
            changeOutputs: int, sendEntireBalance: bool, recipients: List[str],
            slateVersion=0, strategy=0, addressOpt={}):
        pass


    def buildWalletTx(
            self, walletTxId: int, txOffset: BlindingFactor,
            inputs: List[Nugget], changeOutputs: List[Nugget],
            slate: Slate, addressOpt: str, proofOpt: SlatePaymentProof):
        pass

