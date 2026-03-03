"""
mimblewimble/p2p/adapter.py

ChainAdapter — abstract base class that the P2P layer calls back into the
chain / sync layer when messages are received.

This adaptor pattern decouples the networking code from the chain state,
allowing easy testing with mock adapters.

Reference: p2p/src/types.rs (ChainAdapter trait in Grin)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple


class ChainAdapter(ABC):
    """Abstract interface from the P2P layer into the chain layer.

    All methods are called from the peer receive loop.  Implementations
    must be thread-safe if multiple peers are active.
    """

    # ------------------------------------------------------------------
    # Chain queries (read-only)
    # ------------------------------------------------------------------

    @abstractmethod
    def genesis_hash(self) -> bytes:
        """Return the 32-byte genesis block hash."""

    @abstractmethod
    def total_difficulty(self) -> int:
        """Return current best chain total difficulty."""

    @abstractmethod
    def best_height(self) -> int:
        """Return current best chain height."""

    @abstractmethod
    def get_locator(self) -> List[bytes]:
        """Return a list of header hashes for the GetHeaders locator.

        Usually an exponential step-back through the current chain.
        """

    # ------------------------------------------------------------------
    # Header sync
    # ------------------------------------------------------------------

    @abstractmethod
    def sync_block_headers(self, raw_headers: List[bytes]) -> None:
        """Process a batch of raw serialised headers received from a peer.

        Implementations should validate PoW, chain them, and update the
        block database.
        """

    # ------------------------------------------------------------------
    # Block sync
    # ------------------------------------------------------------------

    @abstractmethod
    def get_block_hash_at_height(self, height: int) -> Optional[bytes]:
        """Return the hash of the canonical block at *height*, or None."""

    # ------------------------------------------------------------------
    # TxHashSet snapshot
    # ------------------------------------------------------------------

    @abstractmethod
    def txhashset_write(
        self,
        block_hash: bytes,
        height: int,
        zip_bytes: bytes,
    ) -> bool:
        """Validate and apply a TxHashSet ZIP archive.

        Returns True if the ZIP was accepted and the chain state updated.
        """

    # ------------------------------------------------------------------
    # PIBD segments
    # ------------------------------------------------------------------

    @abstractmethod
    def receive_bitmap_segment(self, block_hash: bytes, segment) -> None:
        """Process an inbound bitmap segment."""

    @abstractmethod
    def receive_output_segment(self, block_hash: bytes, segment) -> None:
        """Process an inbound output PMMR segment."""

    @abstractmethod
    def receive_rangeproof_segment(self, block_hash: bytes, segment) -> None:
        """Process an inbound rangeproof PMMR segment."""

    @abstractmethod
    def receive_kernel_segment(self, block_hash: bytes, segment) -> None:
        """Process an inbound kernel MMR segment."""


class NoopChainAdapter(ChainAdapter):
    """Dummy adapter that does nothing — useful for unit-testing the P2P layer."""

    def genesis_hash(self) -> bytes:
        return b"\x00" * 32

    def total_difficulty(self) -> int:
        return 0

    def best_height(self) -> int:
        return 0

    def get_locator(self) -> List[bytes]:
        return [b"\x00" * 32]

    def sync_block_headers(self, raw_headers: List[bytes]) -> None:
        pass

    def get_block_hash_at_height(self, height: int) -> Optional[bytes]:
        return None

    def txhashset_write(self, block_hash: bytes, height: int, zip_bytes: bytes) -> bool:
        return False

    def receive_bitmap_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_output_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_rangeproof_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_kernel_segment(self, block_hash: bytes, segment) -> None:
        pass
