from typing import Dict, List, Optional
from uuid import UUID

from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.entity import OutputDataEntity
from mimblewimble.models.transaction import EOutputStatus, TransactionKernel


class WalletStorage:
    # Outputs
    def get_all_outputs(self) -> List[OutputDataEntity]:
        raise NotImplementedError

    def get_outputs_by_status(self, status: EOutputStatus) -> List[OutputDataEntity]:
        raise NotImplementedError

    def is_output_known(self, commitment: bytes) -> bool:
        raise NotImplementedError

    def add_output(
        self, output: OutputDataEntity, kernel: Optional[TransactionKernel] = None
    ):
        """Add new output (e.g., receive or coinbase). Kernel optional for coinbase/confirmed."""
        raise NotImplementedError

    def update_output(self, output: OutputDataEntity):
        """Update status, height, etc. (e.g., lock, spend, confirm, mature)."""
        raise NotImplementedError

    def mark_output_spent(self, commitment: bytes):
        """Helper for refresh: mark as spent."""
        raise NotImplementedError

    # Transactions / Slates
    def save_slate_context(
        self,
        slate_id: UUID | str,
        slate,
        secret_key: Optional[bytes | SecretKey] = None,
        secret_nonce: Optional[bytes | SecretKey] = None,
        kernel: Optional[TransactionKernel] = None,
    ):
        """Save in-progress or confirmed slate + blinding secrets."""
        raise NotImplementedError

    def get_slate_context(self, slate_id: UUID) -> Optional[Dict]:
        """Return dict with slate, secrets, kernel."""
        raise NotImplementedError

    def get_tx_kernel(self, slate_id: UUID) -> Optional[TransactionKernel]:
        """Get kernel for confirmed tx."""
        raise NotImplementedError

    def delete_slate_context(self, slate_id: UUID):
        """Cleanup after cancel or full confirm."""
        raise NotImplementedError

    # Misc
    def commit(self):
        """Flush changes (useful for DB impl)."""
        pass


class WalletStorageInMemory(WalletStorage):
    def __init__(self):
        self.outputs: List[OutputDataEntity] = []  # All outputs (active + spent)
        self.txs: Dict[UUID, Dict] = {}  # slate_id -> context

    # Outputs
    def get_all_outputs(self) -> List[OutputDataEntity]:
        return self.outputs[:]

    def get_outputs_by_status(self, status: EOutputStatus) -> List[OutputDataEntity]:
        return [o for o in self.outputs if o.status == status]

    def is_output_known(self, commitment: bytes) -> bool:
        for o in self.outputs:
            if o.output.commitment.getBytes() == commitment:
                return True
        return False

    def add_output(
        self, output: OutputDataEntity, kernel: Optional[TransactionKernel] = None
    ):
        # For coinbase: set status=IMMATURE, link kernel if needed
        self.outputs.append(output)

        # TODO
        # if kernel and output.is_coinbase:  # assume flag or check features
        #    # Optional: store kernel separately or in output
        #    pass

    def update_output(self, updated_output: OutputDataEntity):
        for i, o in enumerate(self.outputs):
            if (
                o.output.commitment == updated_output.output.commitment
            ):  # assume unique commitment
                self.outputs[i] = updated_output
                return
        raise ValueError("Output not found")

    def mark_output_spent(self, commitment: bytes):
        for o in self.outputs:
            if o.output.commitment == commitment:
                o.output.status = EOutputStatus.SPENT
                return

    # Slates / Txs
    def save_slate_context(
        self, slate_id: UUID, slate, secret_key=None, secret_nonce=None, kernel=None
    ):
        self.txs[slate_id] = {
            "slate": slate,
            "secret_key": secret_key,
            "secret_nonce": secret_nonce,
            "kernel": kernel,  # None for in-progress, set on finalize/post
        }

    def get_slate_context(self, slate_id: UUID) -> Optional[Dict]:
        return self.txs.get(slate_id)

    def get_tx_kernel(self, slate_id: UUID) -> Optional[TransactionKernel]:
        ctx = self.txs.get(slate_id)
        return ctx["kernel"] if ctx else None

    def delete_slate_context(self, slate_id: UUID):
        self.txs.pop(slate_id, None)
