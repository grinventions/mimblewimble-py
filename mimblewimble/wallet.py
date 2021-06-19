
class Output:
    def __init__(self, oid, commitment, status, txid, encrypted):
        self.oid = oid
        self.commitment = commitment
        self.status = status
        self.txid = txid
        self.encrypted = encrypted


class Slate:
    def __init__(self, slate_id, stage, iv, slate, armored_slatepack):
        self.slate_id = slate_id
        self.stage = stage
        self.iv = iv # 16 bytes
        self.slate = slate
        self.armorder_slatepack = armored_slatepack


def TransactionBuilder(inputs, outputs, kernel, offset: BlindingFactor):
        body = TransactionBody(transactionInputs, transactionOutputs, kernels)
        return Transaction(BlindingFactor(transactionOffset), body)


class Wallet:
    def __init__(self, next_tx_id, refresh_block_height, restore_leaf_index):
        self.next_tx_id = next_tx_id
        self.refresh_block_height = refresh_block_height
        self.restore_leaf_index = restore_leaf_index

