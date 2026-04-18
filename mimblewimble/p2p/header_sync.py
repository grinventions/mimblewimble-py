"""
mimblewimble/p2p/header_sync.py

Stage 1 of PIBD sync: header-only synchronisation.

Algorithm (mirrors Grin's servers/src/grin/sync/header_sync.rs):

  1. Select the peer with the highest reported total difficulty.
  2. Build a locator — an exponentially step-backed list of known header
     hashes anchoring the request to our current chain tip.
  3. Send GetHeaders(locator) to the best peer.
  4. Receive Headers(…) and hand each raw header to the ChainAdapter via
     ``sync_block_headers()``.
  5. Repeat until no new headers are returned (we are at the same height as
     the peer) or until interrupted.

A single :class:`HeaderSync` instance is held by the :class:`SyncRunner`
and its ``check_run()`` method is called periodically.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import List, Optional

from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.peers import HeaderRecord, PeerStore
from mimblewimble.p2p.message import (
    MAX_HEADERS,
    MessageType,
    MsgGetHeaders,
    MsgHeaders,
    MsgPing,
    MsgPong,
)
from mimblewimble.p2p.peer import Peer, DEAD_TIMEOUT
from mimblewimble.p2p.peers import PeerStore

log = logging.getLogger(__name__)

# Wait this many seconds between header-sync rounds
HEADER_SYNC_INTERVAL: float = 10.0

# Maximum locator length (exponential step-back)
LOCATOR_SIZE: int = 20

# Minimum number of connected peers before we attempt to sync
MIN_PEERS: int = 1


class HeaderSync:
    """Stage-1 PIBD sync: download and validate block headers.

    Instantiated by :class:`SyncRunner`; its ``check_run()`` method is
    called every iteration of the main sync loop.
    """

    def __init__(
        self,
        adapter: ChainAdapter,
        peers: PeerStore,
    ) -> None:
        self._adapter = adapter
        self._peers = peers
        self._last_sync_at: float = 0.0
        self._current_peer: Optional[Peer] = None

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    def check_run(
        self, total_difficulty: int, sync_peers_total_difficulty: int
    ) -> bool:
        """Run one header-sync iteration if conditions are met.

        Returns:
            True if we sent a GetHeaders request (i.e. sync is in progress).
            False if conditions are not met (not enough peers, already up-to-date).
        """
        if not self._header_sync_due():
            return False

        peer = self._choose_sync_peer(sync_peers_total_difficulty)
        if peer is None:
            log.debug("HeaderSync: no suitable peer found")
            return False

        self._current_peer = peer
        locator = self._adapter.get_locator()
        log.debug(
            "HeaderSync: requesting headers from %s (locator len=%d)",
            peer.addr,
            len(locator),
        )
        peer.request_headers(locator)
        self._last_sync_at = time.monotonic()
        return True

    # ------------------------------------------------------------------
    # Locator construction (used by the adapter or directly)
    # ------------------------------------------------------------------

    @staticmethod
    def build_locator(height: int, get_hash_fn) -> List[bytes]:
        """Build an exponential step-back locator for *height*.

        Args:
            height          Current chain tip height.
            get_hash_fn     Callable(height) → Optional[bytes] — returns the
                            block hash at the given height, or None.

        Returns:
            List of up to ``LOCATOR_SIZE`` 32-byte block hashes.
        """
        locator: List[bytes] = []
        step = 1
        h = height
        # Reserve one slot for genesis, so the final list stays within LOCATOR_SIZE.
        while h > 0 and len(locator) < LOCATOR_SIZE - 1:
            block_hash = get_hash_fn(h)
            if block_hash is not None:
                locator.append(block_hash)
            h = max(0, h - step)
            if len(locator) >= 10:
                step *= 2
        # Always include genesis
        genesis = get_hash_fn(0)
        if genesis is not None and (not locator or locator[-1] != genesis):
            locator.append(genesis)
        return locator

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _header_sync_due(self) -> bool:
        """Return True if enough time has passed since the last sync."""
        return (time.monotonic() - self._last_sync_at) >= HEADER_SYNC_INTERVAL

    def _choose_sync_peer(self, min_total_difficulty: int) -> Optional[Peer]:
        """Select the best peer for header sync."""
        peer = self._peers.live().highest_difficulty().pick()
        return peer


# ---------------------------------------------------------------------------
# Inline header application (for adapters that push headers directly here)
# ---------------------------------------------------------------------------


def apply_headers_message(
    adapter: ChainAdapter,
    raw_headers: List[bytes],
    peer_addr: str = "",
    peers: Optional[PeerStore] = None,
) -> int:
    """Apply a batch of raw serialised headers from *peer_addr*.

    Calls ``adapter.sync_block_headers(raw_headers)`` and returns the count.

    This is the callback invoked when a Headers message arrives in the
    peer's receive loop.
    """
    if not raw_headers:
        return 0
    log.info(
        "Applying %d headers from peer %s",
        len(raw_headers),
        peer_addr,
    )

    if peers is not None:
        header_records = [
            HeaderRecord(
                hash_hex=hashlib.blake2b(raw_header, digest_size=32).hexdigest(),
                height=idx,
                raw=raw_header,
            )
            for idx, raw_header in enumerate(raw_headers)
        ]
        peers.store_headers(header_records)

    adapter.sync_block_headers(raw_headers)
    return len(raw_headers)


# Module-level alias so tests can either import build_locator directly
# or call HeaderSync.build_locator - both work identically.
build_locator = HeaderSync.build_locator
