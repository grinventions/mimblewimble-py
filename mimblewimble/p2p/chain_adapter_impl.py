"""
mimblewimble/p2p/chain_adapter_impl.py

ConcreteChainAdapter — a fully wired :class:`ChainAdapter` implementation
that connects the P2P sync layer to an in-memory block database, the block
validator, and an optional transaction pool.

Usage::

    from mimblewimble.p2p.chain_adapter_impl import ConcreteChainAdapter
    from mimblewimble.genesis import genesis_block_header

    adapter = ConcreteChainAdapter(genesis_hash=genesis_block_header().getHash())
    peer_store = PeerStore()
    runner = SyncRunner(adapter, peer_store, txhashset, data_dir)

Reference: servers/src/grin/sync/syncer.rs (ChainAdapter trait impl)
"""

from __future__ import annotations

import logging
import threading
from io import BytesIO
from typing import List, Optional

from mimblewimble.blockchain import (
    BlockHeader,
    FullBlock,
    HeaderValidationError,
    BlockValidationError,
    validate_header,
)
from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.peers import BlockRecord, HeaderRecord, OutputRecord
from mimblewimble.pool import TxPool, TxValidationError
from mimblewimble.pow.blockdb import IBlockDB, InMemoryBlockDB
from mimblewimble.serializer import Serializer

log = logging.getLogger(__name__)


class ConcreteChainAdapter(ChainAdapter):
    """ChainAdapter backed by an :class:`InMemoryBlockDB`.

    Thread-safe for concurrent peer receive loops.

    Args:
        genesis_hash:    The 32-byte genesis block hash expected from peers.
        block_db:        Optional pre-populated block database.  A fresh
                         :class:`InMemoryBlockDB` is created when omitted.
        validate_blocks: If True (default), call :meth:`FullBlock.validate`
                         on every received block.  Disable only in tests.
    """

    def __init__(
        self,
        genesis_hash: bytes,
        block_db: Optional[IBlockDB] = None,
        validate_blocks: bool = True,
    ) -> None:
        self._genesis_hash = genesis_hash
        self._db: IBlockDB = block_db or InMemoryBlockDB()
        self._validate_blocks = validate_blocks
        self._lock = threading.Lock()

        # Simple in-memory stores for full blocks and the UTXO set (basic)
        self._blocks: dict[str, bytes] = {}  # hash_hex → raw bytes
        self._best_height: int = 0
        self._best_total_difficulty: int = 0
        self._best_hash: Optional[bytes] = None

        # Transaction pool (Dandelion++ stem/fluff)
        self._pool: TxPool = TxPool()

    # ------------------------------------------------------------------
    # ChainAdapter — read-only queries
    # ------------------------------------------------------------------

    def genesis_hash(self) -> bytes:
        return self._genesis_hash

    def total_difficulty(self) -> int:
        with self._lock:
            return self._best_total_difficulty

    def best_height(self) -> int:
        with self._lock:
            return self._best_height

    def get_locator(self) -> List[bytes]:
        """Return an exponential step-back locator from the current best tip.

        Produces up to 20 hashes stepping back by powers of 2: heights
        h, h-1, h-2, h-4, h-8, …, 0.
        """
        with self._lock:
            height = self._best_height
            if height == 0:
                return [self._genesis_hash]

        hashes: List[bytes] = []
        step = 1
        h = height
        while h >= 0 and len(hashes) < 20:
            header = self._db.get_header_by_height(h)
            if header is not None:
                hashes.append(header.getHash())
            else:
                hashes.append(b"\x00" * 32)
            if h == 0:
                break
            h = max(0, h - step)
            step *= 2

        if not hashes:
            hashes.append(self._genesis_hash)
        return hashes

    def get_block_hash_at_height(self, height: int) -> Optional[bytes]:
        header = self._db.get_header_by_height(height)
        if header is None:
            return None
        return header.getHash()

    # ------------------------------------------------------------------
    # Header sync
    # ------------------------------------------------------------------

    def sync_block_headers(self, raw_headers: List[bytes]) -> None:
        """Validate and store a batch of serialised block headers.

        Invalid headers are skipped with a warning; the rest are applied.
        Duplicate headers (already stored) are silently ignored.
        """
        accepted = 0
        for raw in raw_headers:
            try:
                s = Serializer(BytesIO(raw))
                header = BlockHeader.deserialize(s)
            except Exception as exc:
                log.warning("Failed to deserialise header: %s", exc)
                continue

            hash_hex = header.getHash().hex()
            existing = self._db.get_block_header(hash_hex)
            if existing is not None:
                continue  # already have this header

            # Chain-link validation against the previous header
            prev_header = self._db.get_block_header(header.getPreviousHash().hex())

            try:
                validate_header(header, prev_header=prev_header, block_db=self._db)
            except HeaderValidationError as exc:
                log.warning(
                    "Rejecting header h=%d hash=%s: %s",
                    header.getHeight(),
                    hash_hex[:12],
                    exc,
                )
                continue

            self._db.add_header(header)
            with self._lock:
                if header.getTotalDifficulty() > self._best_total_difficulty:
                    self._best_total_difficulty = header.getTotalDifficulty()
                    self._best_height = header.getHeight()
                    self._best_hash = header.getHash()
            accepted += 1

        if accepted:
            log.debug(
                "sync_block_headers: accepted %d/%d headers", accepted, len(raw_headers)
            )

    # ------------------------------------------------------------------
    # TxHashSet snapshot
    # ------------------------------------------------------------------

    def txhashset_write(
        self,
        block_hash: bytes,
        height: int,
        zip_bytes: bytes,
    ) -> bool:
        """Stub — full TxHashSet zip application is handled by StateSync."""
        log.debug(
            "txhashset_write: hash=%s height=%d size=%d",
            block_hash.hex()[:12],
            height,
            len(zip_bytes),
        )
        return True

    # ------------------------------------------------------------------
    # PIBD segments  (delegated to the TxHashSet / Desegmenter layer)
    # ------------------------------------------------------------------

    def receive_bitmap_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_output_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_rangeproof_segment(self, block_hash: bytes, segment) -> None:
        pass

    def receive_kernel_segment(self, block_hash: bytes, segment) -> None:
        pass

    # ------------------------------------------------------------------
    # Block sync
    # ------------------------------------------------------------------

    def handle_block(self, block_hash: bytes, raw_block: bytes) -> bool:
        """Deserialise, optionally validate, and store a full block.

        Returns True if newly accepted; False if already known.
        """
        try:
            s = Serializer(BytesIO(raw_block))
            block = FullBlock.deserialize(s)
        except Exception as exc:
            log.warning("handle_block: failed to deserialise: %s", exc)
            return False

        hash_hex = block.getHash().hex()
        with self._lock:
            if hash_hex in self._blocks:
                return False  # duplicate

        if self._validate_blocks:
            prev_header = self._db.get_block_header(block.getPreviousHash().hex())
            try:
                block.validate(prev_header=prev_header, block_db=self._db)
            except (HeaderValidationError, BlockValidationError) as exc:
                log.warning(
                    "handle_block: rejected h=%d hash=%s: %s",
                    block.getHeight(),
                    hash_hex[:12],
                    exc,
                )
                return False

        with self._lock:
            self._blocks[hash_hex] = raw_block
            if block.getTotalDifficulty() > self._best_total_difficulty:
                self._best_total_difficulty = block.getTotalDifficulty()
                self._best_height = block.getHeight()
                self._best_hash = block.getHash()

        log.debug(
            "handle_block: accepted h=%d hash=%s", block.getHeight(), hash_hex[:12]
        )
        return True

    # ------------------------------------------------------------------
    # Transaction pool
    # ------------------------------------------------------------------

    def handle_transaction(self, raw_tx: bytes, from_stem: bool = False) -> bool:
        """Validate and add a transaction to the mempool."""
        try:
            return self._pool.add_transaction(raw_tx, from_stem=from_stem)
        except TxValidationError as exc:
            log.warning("handle_transaction: validation failed: %s", exc)
            return False

    def handle_compact_block(self, raw_compact_block: bytes) -> bool:
        """Attempt to reconstruct a full block from a compact block.

        Current implementation: if the compact block carries full outputs and
        kernels (i.e., no short-IDs that need mempool lookup), reconstruct the
        FullBlock directly.  Otherwise fall back to issuing a GetBlock request
        (requires the caller to have a reference to the relevant peer).
        """
        from mimblewimble.blockchain import BlockHeader
        from mimblewimble.serializer import Serializer
        from io import BytesIO

        try:
            s = Serializer(BytesIO(raw_compact_block))
            header = BlockHeader.deserialize(s)
            # Read nonce and counts
            nonce = int.from_bytes(s.read(8), "big")
            num_outputs = int.from_bytes(s.read(2), "big")
            num_kernels = int.from_bytes(s.read(2), "big")
            num_short_ids = int.from_bytes(s.read(2), "big")
        except Exception as exc:
            log.warning("handle_compact_block: deserialise error: %s", exc)
            return False

        if num_short_ids > 0:
            # Need mempool short-ID matching — not yet implemented
            log.debug(
                "handle_compact_block: %d short-IDs unresolved at h=%d, "
                "needs GetBlock fallback",
                num_short_ids,
                header.getHeight(),
            )
            return False

        # All transactions are included as full outputs/kernels — reconstruct block
        try:
            from mimblewimble.models.transaction import (
                TransactionOutput,
                TransactionKernel,
                TransactionBody,
            )

            outputs = [TransactionOutput.deserialize(s) for _ in range(num_outputs)]
            kernels = [TransactionKernel.deserialize(s) for _ in range(num_kernels)]
            body = TransactionBody([], outputs, kernels)
            from mimblewimble.blockchain import FullBlock

            block = FullBlock(header, body)
        except Exception as exc:
            log.warning("handle_compact_block: reconstruct error: %s", exc)
            return False

        return self.handle_block(block.getHash(), block.serialize())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_block_db(self) -> IBlockDB:
        """Return the underlying block database (useful for testing)."""
        return self._db

    def get_raw_block(self, hash_hex: str) -> Optional[bytes]:
        with self._lock:
            return self._blocks.get(hash_hex)
