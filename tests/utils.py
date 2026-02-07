from typing import Dict, List, Optional

from mimblewimble.entity import OutputDataEntity
from mimblewimble.wallet import NodeAccess
from mimblewimble.models.transaction import Transaction, TransactionOutput, EKernelFeatures


class MockNode(NodeAccess):
    def __init__(self, initial_height: int = 100000):
        self.block_height: int = initial_height

        # until we have a real PMMR implementation I am using
        # this simplified one, which is basically a list of
        # all outputs ever seen on chain, with their heights and spent status
        # the start index is the minimum index such that all the lower ones are spent
        # and end index is highest index in that list
        self.pmmr_start_index = 0
        self.pmmr_end_index = 0
        self.fake_pmmr = []

        # Known commitments on chain → (height_found, is_spent)
        self.chain_outputs: Dict[bytes, tuple[int, bool]] = {}

        # Known kernel excesses on chain → height_found
        self.chain_kernels: Dict[bytes, int] = {}

        # Pending transactions (not yet mined)
        self.mempool: List[Transaction] = []

    # --- NodeAccess methods ---

    def get_current_block_height(self) -> int:
        return self.block_height

    def get_outputs(
            self,
            commitments: List[bytes],
            include_proof: bool = True
    ) -> Dict[bytes, Dict]:
        """
        Simulate /v2/foreign/get_outputs
        Returns info for each commitment if it's on chain.
        """
        result = {}
        for commit in commitments:
            if commit in self.chain_outputs:
                height, spent, range_proof = self.chain_outputs[commit]
                result[commit] = {
                    "commit": "09" + commit.hex(),
                    "height": height,
                    "mmr_index": 12345,  # dummy
                    "spent": spent,
                    "proof": range_proof.hex()
                }
        return result

    def get_unspent_outputs(self, start_index, end_index, window_size, range_proof=False):
        """Get unspent outputs in PMMR index range."""
        outputs = []
        max_index = min(end_index, start_index + window_size)
        last_retrieved_index = start_index
        for i, commitment in enumerate(self.fake_pmmr[start_index:max_index+1]):
            if commitment in self.chain_outputs:
                height, spent, range_proof = self.chain_outputs[commitment]
                if not spent:
                    outputs.append({
                        "commit": "09" + commitment.hex(),
                        "height": height,
                        "mmr_index": start_index + i,
                        "proof": range_proof.hex()
                    })
            last_retrieved_index += 1
        return {
            'outputs': outputs,
            'last_retrieved_index': last_retrieved_index,
            'highest_index': end_index
        }

    def get_pmmr_indices(self, start_block_height: int, end_block_height: int) -> Dict:
        """Get MMR indices for outputs and kernels in block range."""
        return {
            'last_retrieved_index': self.pmmr_start_index,
            'highest_index': self.pmmr_end_index
        }

    def get_kernel(self, excess: bytes) -> Optional[Dict]:
        """
        Simulate /v2/foreign/get_kernel
        """
        if excess in self.chain_kernels:
            height = self.chain_kernels[excess]
            return {
                "kernel": {"excess": "08" + excess.hex()},
                "height": height,
                "mmr_index": 54321
            }
        return None

    def push_transaction(self, transaction: Transaction, fluff: bool = True) -> bool:
        """
        Add tx to mempool. It will be mined when mine() is called.
        """
        self.mempool.append(transaction)
        return True

    # --- Mock control methods ---

    def mine(self, blocks: int = 1):
        """
        Advance chain by N blocks and mine all mempool txs.
        """
        # TODO update the self.start_index and self.end_index to reflect the new outputs and kernels mined into the chain
        for _ in range(blocks):
            self.block_height += 1

            # Mine all pending txs into this block
            for tx in self.mempool[:]:  # copy because we remove
                self._include_transaction(tx, self.block_height)
                # print('including tx', tx.body.kernels[0].getExcessCommitment().getBytes().hex())
                self.mempool.remove(tx)

                # mark inputs as spent if not a coinbase
                for input in tx.body.inputs:
                    commit = input.getCommitment().getBytes()
                    if commit in self.chain_outputs:
                        # print('spending', commit.hex())
                        height, _, proof = self.chain_outputs[commit]
                        self.chain_outputs[commit] = (height, True, proof)

                # add output commitments to chain_outputs
                for output in tx.body.outputs:
                    range_proof = output.getRangeProof() if hasattr(output, 'getRangeProof') else None
                    if isinstance(output, OutputDataEntity):
                        commit = output.output.getCommitment().getBytes()
                    if isinstance(output, TransactionOutput):
                        commit = output.getCommitment().getBytes()
                    self.chain_outputs[commit] = (self.block_height, False, range_proof)

                    # add commitment into fake PMMR
                    self.fake_pmmr.append(commit)

                # add kernel excesses to chain_kernels
                for kernel in tx.body.kernels:
                    self.chain_kernels[kernel.getExcessCommitment().getBytes()] = self.block_height

        self.mempool.clear()

        # update fake PMMR to reflect the new outputs
        start_index = self.pmmr_end_index
        end_index = self.pmmr_end_index
        highest_unspent = start_index
        for i, commitment in enumerate(self.fake_pmmr[start_index:end_index]):
            pmmr_index = i + start_index
            if commitment in self.chain_outputs:
                height, spent = self.chain_outputs[commitment]
                if spent:
                    highest_unspent = pmmr_index + 1
        self.pmmr_start_index = highest_unspent
        self.pmmr_end_index = len(self.fake_pmmr)-1

    def _include_transaction(self, tx: Transaction, height: int):
        """
        Register outputs and kernel as confirmed at given height.
        """
        # Register outputs
        for output in tx.body.outputs:
            range_proof = output.getRangeProof() if hasattr(output, 'getRangeProof') else None
            if isinstance(output, OutputDataEntity):
                commit = output.output.getCommitment().getBytes()
            if isinstance(output, TransactionOutput):
                commit = output.getCommitment().getBytes()  # assume method or attr
            self.chain_outputs[commit] = (height, False, range_proof)  # not spent yet

        # Register kernel
        for kernel in tx.body.kernels:
            excess = kernel.getExcessCommitment().getBytes()
            self.chain_kernels[excess] = height

    def spend_output(self, commitment: bytes):
        """
        Simulate someone else spending your output.
        Useful for testing refresh detecting spent coins.
        """
        if commitment in self.chain_outputs:
            height, _ = self.chain_outputs[commitment]
            self.chain_outputs[commitment] = (height, True, None)

    def add_fake_output(self, commitment: bytes, height: int, spent: bool = False, proof: Optional[bytes] = None):
        """
        Manually inject an output (e.g., received via slatepack offline).
        """
        self.chain_outputs[commitment] = (height, spent, proof)

    def add_fake_kernel(self, excess: bytes, height: int):
        """
        Manually inject a kernel.
        """
        self.chain_kernels[excess] = height

    def how_many_unspent(self):
        return sum(1 for _, (height, spent, _) in self.chain_outputs.items() if not spent)