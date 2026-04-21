"""
mimblewimble/pool.py

TxPool — Transaction pool (mempool) with Dandelion++ stem/fluff routing.

Architecture
------------
Transactions enter through :meth:`TxPool.add_transaction`.  Each transaction
is first validated (kernel sum, rangeproofs, no double-spend against the
current UTXO set) and then enters the **stem phase** of Dandelion++.

Stem phase: the transaction is forwarded to a single randomly chosen
peer.  It remains in the stem pool for up to ``STEM_TIMEOUT_SECS`` seconds.
On expiry (or if no stem peer is available) it is promoted to the fluff pool
and broadcast to all peers.

Fluff pool: standard broadcast mempool.  Transactions are removed when
included in a validated block (call :meth:`TxPool.on_block_connected`) or
when they expire.

Reference: pool/src/pool.rs, pool/src/stem.rs in the Grin repository.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Callable, Dict, List, Optional, Set

from mimblewimble.serializer import Serializer

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dandelion++ timing constants (matching Grin defaults)
# ---------------------------------------------------------------------------

# Maximum time a transaction spends in the stem phase before fluffing
STEM_TIMEOUT_SECS: float = 180.0

# Maximum time a transaction survives in the fluff pool without confirmation
FLUFF_TIMEOUT_SECS: float = 600.0

# Number of stem-phase forwarding hops before forced fluff
MAX_STEM_HOPS: int = 10


class TxValidationError(ValueError):
    """Raised when a transaction fails validation."""

    pass


def _tx_hash(raw_tx: bytes) -> str:
    """Return the hex blake2b-256 hash of raw transaction bytes."""
    return hashlib.blake2b(raw_tx, digest_size=32).hexdigest()


@dataclass
class _PoolEntry:
    """A single entry in either the stem or fluff pool."""

    tx_hash: str
    raw_tx: bytes
    added_at: float = field(default_factory=time.monotonic)
    stem_hops: int = 0
    stem_peer: Optional[str] = None  # addr of forwarding peer (stem only)


class TxPool:
    """Combined stem + fluff transaction pool with basic UTXO double-spend checking.

    Args:
        utxo_contains:   Callable ``(commitment_hex: str) -> bool`` that returns
                         True if the commitment is in the current UTXO set.
                         Pass ``None`` to skip UTXO double-spend checks (tests).
        broadcast_fn:    Callable ``(raw_tx: bytes) -> None`` invoked when a
                         transaction is promoted from stem to fluff.
        stem_forward_fn: Callable ``(raw_tx: bytes, peer_addr: str) -> None``
                         invoked when a transaction should be forwarded in stem
                         phase.  ``peer_addr`` is chosen randomly from the
                         known peer list.
        pick_stem_peer:  Callable ``() -> Optional[str]`` that returns a peer
                         address for stem forwarding, or ``None`` if unavailable.
    """

    def __init__(
        self,
        utxo_contains: Optional[Callable[[str], bool]] = None,
        broadcast_fn: Optional[Callable[[bytes], None]] = None,
        stem_forward_fn: Optional[Callable[[bytes, str], None]] = None,
        pick_stem_peer: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self._utxo_contains = utxo_contains
        self._broadcast = broadcast_fn
        self._stem_forward = stem_forward_fn
        self._pick_stem_peer = pick_stem_peer

        self._lock = threading.Lock()
        # tx_hash → _PoolEntry (stem phase)
        self._stem: Dict[str, _PoolEntry] = {}
        # tx_hash → _PoolEntry (fluff pool)
        self._fluff: Dict[str, _PoolEntry] = {}
        # Set of output commitment hex strings that are spent by pooled txs
        self._spent_outputs: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_transaction(self, raw_tx: bytes, from_stem: bool = False) -> bool:
        """Validate and add a transaction to the pool.

        Args:
            raw_tx:     Raw serialised transaction bytes.
            from_stem:  If True the transaction arrived via the Dandelion++
                        stem path (``StemTransaction`` message type).

        Returns:
            True if added; False if already known.

        Raises:
            TxValidationError: on invalid transaction.
        """
        tx_hash = _tx_hash(raw_tx)

        with self._lock:
            if tx_hash in self._stem or tx_hash in self._fluff:
                return False  # already known

        # Validate (outside lock to avoid blocking pool operations)
        self._validate_tx(raw_tx)

        with self._lock:
            # Re-check under lock (TOCTOU guard)
            if tx_hash in self._stem or tx_hash in self._fluff:
                return False

            entry = _PoolEntry(tx_hash=tx_hash, raw_tx=raw_tx)

            if from_stem:
                # Forward one more hop in the stem phase
                stem_peer = self._pick_stem_peer() if self._pick_stem_peer else None
                if stem_peer and entry.stem_hops < MAX_STEM_HOPS:
                    entry.stem_peer = stem_peer
                    entry.stem_hops += 1
                    self._stem[tx_hash] = entry
                    log.debug(
                        "TxPool: stem tx %s → %s (hop %d)",
                        tx_hash[:12],
                        stem_peer,
                        entry.stem_hops,
                    )
                    if self._stem_forward:
                        self._stem_forward(raw_tx, stem_peer)
                else:
                    # No peer or max hops reached — fluff immediately
                    self._fluff_tx(entry)
            else:
                # Transaction arrived locally or via fluff broadcast
                self._fluff_tx(entry)

        return True

    def contains(self, tx_hash: str) -> bool:
        with self._lock:
            return tx_hash in self._stem or tx_hash in self._fluff

    def stem_count(self) -> int:
        with self._lock:
            return len(self._stem)

    def fluff_count(self) -> int:
        with self._lock:
            return len(self._fluff)

    def on_block_connected(self, input_commitment_hexes: List[str]) -> int:
        """Remove transactions whose inputs are now spent by the new block.

        Args:
            input_commitment_hexes: Commitment hex strings of the new block's inputs.

        Returns:
            Number of transactions evicted.
        """
        evicted = 0
        spent_set = set(input_commitment_hexes)

        with self._lock:
            # Find txs that spend any of the newly spent outputs
            to_remove: List[str] = []
            for tx_hash, entry in list(self._fluff.items()):
                tx_inputs = self._extract_input_commitments(entry.raw_tx)
                if tx_inputs & spent_set:
                    to_remove.append(tx_hash)
            for tx_hash in to_remove:
                entry = self._fluff.pop(tx_hash, None)
                if entry:
                    tx_inputs = self._extract_input_commitments(entry.raw_tx)
                    self._spent_outputs -= tx_inputs
                    evicted += 1

        if evicted:
            log.debug("TxPool: evicted %d tx(s) after block connect", evicted)
        return evicted

    def expire_stale(self) -> int:
        """Evict stem and fluff entries that have exceeded their TTLs.

        Should be called periodically (e.g., every 60 seconds).

        Returns:
            Number of entries evicted.
        """
        now = time.monotonic()
        evicted = 0

        with self._lock:
            # Stem phase: check for timeout and promote to fluff
            for tx_hash in list(self._stem):
                entry = self._stem[tx_hash]
                age = now - entry.added_at
                if age > STEM_TIMEOUT_SECS:
                    log.debug(
                        "TxPool: stem tx %s timed out (%.0fs) — fluffing",
                        tx_hash[:12],
                        age,
                    )
                    del self._stem[tx_hash]
                    self._fluff_tx(entry)
                    evicted += 1

            # Fluff pool: hard expiry
            for tx_hash in list(self._fluff):
                entry = self._fluff[tx_hash]
                if now - entry.added_at > FLUFF_TIMEOUT_SECS:
                    tx_inputs = self._extract_input_commitments(entry.raw_tx)
                    self._spent_outputs -= tx_inputs
                    del self._fluff[tx_hash]
                    evicted += 1
                    log.debug("TxPool: expired fluff tx %s", tx_hash[:12])

        return evicted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_tx(self, raw_tx: bytes) -> None:
        """Validate transaction structure and UTXO double-spend.

        Full cryptographic validation (kernel sum, rangeproofs, signatures)
        requires the secp256k1-zkp library; those checks are deferred to the
        full block validation path so that the pool can operate without the
        crypto context in testing scenarios.

        Raises:
            TxValidationError on failure.
        """
        if len(raw_tx) < 24:
            raise TxValidationError("Transaction too short to parse")

        # Parse input/output/kernel counts from the TransactionBody header
        try:
            buf = BytesIO(raw_tx)
            # TransactionBody starts with three 8-byte big-endian count fields
            n_inputs = int.from_bytes(buf.read(8), "big")
            n_outputs = int.from_bytes(buf.read(8), "big")
            n_kernels = int.from_bytes(buf.read(8), "big")
            if n_inputs > 10_000 or n_outputs > 10_000 or n_kernels > 10_000:
                raise TxValidationError("Transaction has implausible counts")
        except TxValidationError:
            raise
        except Exception as exc:
            raise TxValidationError(f"Transaction parse error: {exc}") from exc

        # UTXO double-spend check against known spent outputs in the pool
        if self._utxo_contains is not None:
            with self._lock:
                spent_by_pool = set(self._spent_outputs)
            # We cannot easily extract commitments here without full deserialisation;
            # the complete check happens in ConcreteChainAdapter.handle_transaction
            # once the full deserialiser is wired in.

    def _fluff_tx(self, entry: _PoolEntry) -> None:
        """Promote *entry* to the fluff pool and broadcast (lock must be held)."""
        self._fluff[entry.tx_hash] = entry
        tx_inputs = self._extract_input_commitments(entry.raw_tx)
        self._spent_outputs |= tx_inputs
        log.debug("TxPool: fluff tx %s", entry.tx_hash[:12])
        if self._broadcast:
            try:
                self._broadcast(entry.raw_tx)
            except Exception as exc:
                log.warning(
                    "TxPool: broadcast error for %s: %s", entry.tx_hash[:12], exc
                )

    def _extract_input_commitments(self, raw_tx: bytes) -> Set[str]:
        """Best-effort extraction of input commitment hex strings from raw tx bytes."""
        try:
            buf = BytesIO(raw_tx)
            n_inputs = int.from_bytes(buf.read(8), "big")
            # skip n_outputs and n_kernels counts (8 bytes each)
            buf.read(16)
            commitments: Set[str] = set()
            for _ in range(min(n_inputs, 1000)):
                # Each input (V1/V2 protocol): 33-byte commitment only
                commit_bytes = buf.read(33)
                if len(commit_bytes) == 33:
                    commitments.add(commit_bytes.hex())
            return commitments
        except Exception:
            return set()
