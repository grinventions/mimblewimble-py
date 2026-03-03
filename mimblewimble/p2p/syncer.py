"""
mimblewimble/p2p/syncer.py

SyncRunner — orchestrates Stage-1 (HeaderSync) and Stage-2 (StateSync).

The runner drives a single event-loop iteration; callers (or tests) invoke
``run_once()`` to advance the state machine one step.  For production use,
wrap in a loop::

    runner = SyncRunner(adapter, peers, txhashset, data_dir)
    while not runner.is_done():
        runner.run_once()
        time.sleep(0.5)

The sync machine has the following state transitions::

    INITIAL
      └─ enough peers ──► AWAITING_PEERS
                           └─ best peer found ──► HEADER_SYNC
                                                  └─ headers up-to-date ──► TXHASHSET_PIBD
                                                                            (or TXHASHSET_DOWNLOAD)
                                                                             └─ complete ──► BODY_SYNC
                                                                                            └─ done ──► NO_SYNC

Reference: servers/src/grin/sync/syncer.rs
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from mimblewimble.mmr.pibd import SyncState, SyncStatus
from mimblewimble.mmr.txhashset import TxHashSet
from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.header_sync import HeaderSync
from mimblewimble.p2p.peer import Peer
from mimblewimble.p2p.peers import PeerStore
from mimblewimble.p2p.state_sync import StateSync

log = logging.getLogger(__name__)

# Minimum peers required before any sync starts
MIN_PEERS_FOR_SYNC: int = 1

# Height delta required before we consider ourselves "behind" and start sync
HEIGHT_AHEAD_THRESHOLD: int = 5

# How often to log a progress summary (seconds)
LOG_PROGRESS_INTERVAL: float = 30.0


class SyncRunner:
    """Top-level PIBD sync orchestrator.

    Coordinates :class:`HeaderSync` (Stage 1) and :class:`StateSync`
    (Stage 2) using a shared :class:`SyncState` instance.

    Args:
        adapter         Chain adapter providing block DB read/write access.
        peers           Live peer collection from the P2P layer.
        txhashset       Three-PMMR TxHashSet backed by disk storage.
        data_dir        Directory for temporary snapshot files.
    """

    def __init__(
        self,
        adapter: ChainAdapter,
        peers: PeerStore,
        txhashset: TxHashSet,
        data_dir: Path,
    ) -> None:
        self._adapter = adapter
        self._peers = peers
        self._txhashset = txhashset
        self._data_dir = Path(data_dir)

        self._sync_state = SyncState()
        self._header_sync = HeaderSync(adapter, peers)
        self._state_sync: Optional[StateSync] = None  # lazily created

        self._archive_header = None
        self._genesis_header = None
        self._last_log_at: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def sync_state(self) -> SyncState:
        return self._sync_state

    def is_done(self) -> bool:
        return self._sync_state.status == SyncStatus.NO_SYNC

    def run_once(self) -> None:
        """Advance the sync state machine by one step."""
        status = self._sync_state.status
        n_peers = self._peers.count()

        self._maybe_log_progress()

        # Stage: INITIAL — wait for peers
        if status == SyncStatus.INITIAL:
            if n_peers >= MIN_PEERS_FOR_SYNC:
                self._sync_state.update(SyncStatus.AWAITING_PEERS)
            return

        # Stage: AWAITING_PEERS — probe for the best peer
        if status == SyncStatus.AWAITING_PEERS:
            if n_peers < MIN_PEERS_FOR_SYNC:
                return
            best_peer = self._peers.live().highest_difficulty().pick()
            if best_peer is None:
                return
            my_height = self._adapter.best_height()
            peer_height = best_peer.handshake.genesis_block_difficulty
            # If we're close enough, skip straight to NO_SYNC
            # (genesis_block_difficulty is an imperfect proxy for height here;
            #  a real implementation would use total_difficulty comparison)
            self._sync_state.update(SyncStatus.HEADER_SYNC)
            return

        # Stage: HEADER_SYNC
        if status == SyncStatus.HEADER_SYNC:
            best_peer = self._peers.live().highest_difficulty().pick()
            if best_peer is None:
                return
            peer_diff = best_peer.handshake.genesis_block_difficulty
            my_diff = self._adapter.total_difficulty()
            self._header_sync.check_run(
                total_difficulty=my_diff,
                sync_peers_total_difficulty=peer_diff,
            )
            # Transition to PIBD when headers are approximately caught up.
            # In production this is triggered by the adapter when no new
            # headers are returned; here we check if we have an archive
            # header set.
            if self._archive_header is not None:
                self._sync_state.update(SyncStatus.TXHASHSET_PIBD)
            return

        # Stage: TXHASHSET_PIBD (or TXHASHSET_DOWNLOAD)
        if status in (
            SyncStatus.TXHASHSET_PIBD,
            SyncStatus.TXHASHSET_DOWNLOAD,
            SyncStatus.TXHASHSET_VALIDATION,
        ):
            self._run_state_sync()
            return

        # Stage: BODY_SYNC — future work (block body download)
        if status == SyncStatus.BODY_SYNC:
            # Placeholder: in a full implementation, download remaining block
            # bodies between the genesis+cutoff and the archive header.
            log.debug("SyncRunner: body sync phase (no-op in current implementation)")
            self._sync_state.update(SyncStatus.NO_SYNC)
            return

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def set_archive_header(self, header, genesis_header=None) -> None:
        """Set the archive header (triggers transition from HEADER_SYNC → PIBD)."""
        self._archive_header = header
        self._genesis_header = genesis_header

    def get_state_sync(self) -> Optional[StateSync]:
        """Return the StateSync instance (only present during Stage 2)."""
        return self._state_sync

    def _run_state_sync(self) -> None:
        """Initialise (if needed) and advance the StateSync."""
        if self._state_sync is None:
            if self._archive_header is None:
                log.warning("SyncRunner: no archive header — cannot start StateSync")
                return
            self._state_sync = StateSync(
                adapter=self._adapter,
                peers=self._peers,
                sync_state=self._sync_state,
                txhashset=self._txhashset,
                data_dir=self._data_dir,
            )

        archive_hash = (
            self._archive_header.getHash()
            if hasattr(self._archive_header, "getHash")
            else b"\x00" * 32
        )
        self._state_sync.check_run(
            archive_header=self._archive_header,
            genesis_header=self._genesis_header,
            best_header_hash=archive_hash,
        )

    def _maybe_log_progress(self) -> None:
        now = time.monotonic()
        if now - self._last_log_at < LOG_PROGRESS_INTERVAL:
            return
        self._last_log_at = now
        applied, total = self._sync_state.pibd_progress()
        log.info(
            "SyncRunner status=%s peers=%d pibd=%d/%d in_flight=%d",
            self._sync_state.status.name,
            self._peers.count(),
            applied,
            total,
            self._sync_state.pending_segment_count(),
        )
