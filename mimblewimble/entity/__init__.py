from mimblewimble.models.transaction import EOutputStatus
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import TransactionOutput


class OutputDataEntity:
    def __init__(
        self,
        path: str,
        blinding_factor: BlindingFactor,
        output: TransactionOutput,
        amount: int,
        status: EOutputStatus,
        mmr_index=None,
        block_height=None,
        wallet_tx_id=None,
    ):
        self.path = path
        self.blinding_factor = blinding_factor
        self.output = output
        self.amount = amount
        self.status = status
        self.mmr_index = mmr_index
        self.block_height = block_height
        self.wallet_tx_id = wallet_tx_id

    def getAmount(self):
        return self.amount

    def getBlindingFactor(self):
        return self.blinding_factor

    def getCommitment(self):
        return self.output.getCommitment()

    def getFeatures(self):
        return self.output.getFeatures()

    def getRangeProof(self):
        return self.output.getRangeProof()
