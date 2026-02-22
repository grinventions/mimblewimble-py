from typing import List, Dict

from grinmw import NodeV2Foreign

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

    def get_kernel(
        self, excess: bytes, min_height=None, max_height=None
    ) -> TransactionKernel:
        """Check if kernel exists, return kernel info + height if found."""
        raise NotImplementedError

    def push_transaction(self, transaction: Transaction, fluff=False):
        raise NotImplementedError


class CoreNodeAccess(NodeAccess):
    def __init__(self, foreign_api_url, foreign_api_user, foreign_api_password):
        self.foreign_api_url = foreign_api_url
        self.foreign_api_user = foreign_api_user
        self.foreign_api_password = foreign_api_password
        self.node_client = None

    def connect(self):
        self.node_client = NodeV2Foreign(
            self.foreign_api_url, self.foreign_api_user, self.foreign_api_password
        )

    def get_current_block_height(self):
        return self.node_client.get_tip().get("height", None)

    def get_outputs(
        self,
        outputs: List[OutputDataEntity],
        start_height=None,
        end_height=None,
        include_proof=False,
        include_merkle_proof=False,
    ):
        commits = [output.commitment for output in outputs]
        return self.node_client.get_outputs(
            commits,
            start_height=start_height,
            end_height=end_height,
            include_proof=include_proof,
            include_merkle_proof=include_merkle_proof,
        )

    def get_unspent_outputs(
        self, start_index, end_index, window_size, range_proof=False
    ):
        return self.node_client.get_unspent_outputs(
            start_index, window_size, end_index=window_size, include_proof=range_proof
        )

    def get_pmmr_indices(
        self, start_block_height: int, end_block_height: int
    ) -> Dict[int, List[int]]:
        return self.node_client.get_pmmr_indices(
            start_block_height, end_block_height=end_block_height
        )

    def get_kernel(
        self, excess: bytes, min_height=None, max_height=None
    ) -> TransactionKernel:
        kernel_response = self.node_client.get_kernel(
            excess.hex(), min_height=min_height, max_height=max_height
        )
        if kernel_response is None:
            return None
        return TransactionKernel.fromJSON(kernel_response)

    def push_transaction(self, transaction: Transaction, fluff=False):
        self.node_client.push_transaction(transaction.toJSON(), fluff=fluff)
