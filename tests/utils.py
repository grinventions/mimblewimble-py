from typing import Dict, List, Optional

from mimblewimble.entity import OutputDataEntity
from mimblewimble.wallet import NodeAccess
from mimblewimble.models.transaction import Transaction, TransactionOutput, EKernelFeatures


class MockNode(NodeAccess):
    def __init__(self, initial_height: int = 100000):
        self.block_height: int = initial_height

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
                height, spent = self.chain_outputs[commit]
                result[commit] = {
                    "commit": "09" + commit.hex(),
                    "height": height,
                    "mmr_index": 12345,  # dummy
                    "spent": spent,
                    "proof": None  # not needed in mock
                }
        return result

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
                        height, _ = self.chain_outputs[commit]
                        self.chain_outputs[commit] = (height, True)

                # add output commitments to chain_outputs
                for output in tx.body.outputs:
                    if isinstance(output, OutputDataEntity):
                        commit = output.output.getCommitment().getBytes()
                    if isinstance(output, TransactionOutput):
                        commit = output.getCommitment().getBytes()
                    self.chain_outputs[commit] = (self.block_height, False)


                # add kernel excesses to chain_kernels
                for kernel in tx.body.kernels:
                    self.chain_kernels[kernel.getExcessCommitment().getBytes()] = self.block_height

        self.mempool.clear()

        # print all unspent inputs on chain
        commits_unpsent = []
        commits_spent = []
        for commit, (height, spent) in self.chain_outputs.items():
            if not spent:
                commits_unpsent.append((commit, height))
            else:
                commits_spent.append((commit, height))

        '''
        print('unspent on chain:')
        for commit, height in commits_unpsent:
            print(commit.hex(), 'at height', height)
        print('spent on chain:')
        for commit, height in commits_spent:
            print(commit.hex(), 'at height', height)
        print()
        '''

    def _include_transaction(self, tx: Transaction, height: int):
        """
        Register outputs and kernel as confirmed at given height.
        """
        # Register outputs
        for output in tx.body.outputs:
            if isinstance(output, OutputDataEntity):
                commit = output.output.getCommitment().getBytes()
            if isinstance(output, TransactionOutput):
                commit = output.getCommitment().getBytes()  # assume method or attr
            self.chain_outputs[commit] = (height, False)  # not spent yet

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
            self.chain_outputs[commitment] = (height, True)

    def add_fake_output(self, commitment: bytes, height: int, spent: bool = False):
        """
        Manually inject an output (e.g., received via slatepack offline).
        """
        self.chain_outputs[commitment] = (height, spent)

    def add_fake_kernel(self, excess: bytes, height: int):
        """
        Manually inject a kernel.
        """
        self.chain_kernels[excess] = height