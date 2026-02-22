from typing import List, Dict

from mimblewimble.entity import OutputDataEntity
from mimblewimble.models.transaction import TransactionKernel, Transaction


class NodeAccess:
    def get_current_block_height(self):
        raise NotImplementedError

    # methods consistent with RFC
    # https://docs.grin.mw/grin-rfcs/text/0007-node-api-v2/
    def get_outputs(self, outputs: List[OutputDataEntity]):
        raise NotImplementedError

    def get_unspent_outputs(
        self, start_index, end_index, window_size, range_proof=False
    ):
        """Get unspent outputs in PMMR index range."""
        raise NotImplementedError

    def get_pmmr_indices(
        self, start_block_height: int, end_block_height: int
    ) -> Dict[int, List[int]]:
        """Get MMR indices for outputs and kernels in block range."""
        raise NotImplementedError

    def get_kernel(self, excess: bytes) -> TransactionKernel:
        """Check if kernel exists, return kernel info + height if found."""
        raise NotImplementedError

    def push_transaction(self, transaction: Transaction):
        raise NotImplementedError
