"""
mimblewimble/p2p/body_sync.py

BodySync — Stage 3 of Grin node sync: download full block bodies for the
range between the genesis/horizon and the current best header.

After PIBD (Stage 2) completes we have all UTXO commitments but no block
bodies between the horizon and the chain tip.  BodySync fills that gap by
issuing ``GetBlock`` requests and validating received ``Block`` responses.

The in-flight request pattern mirrors :class:`~mimblewimble.p2p.state_sync.StateSync`.

Reference: servers/src/grin/sync/body_sync.rs
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.peer import Peer
from mimblewimble.p2p.peers import PeerStore

log = logging.getLogger(__name__)

# Maximum number of simultaneous in-flight block requests per peer
BLOCK_REQUEST_BATCH_SIZE: int = 16

# Seconds before an in-flight request is considered stale and re-queued
BLOCK_REQUEST_TIMEOUT_SECS: float = 30.0

# How often (seconds) to log a body-sync progress summary
LOG_INTERVAL: float = 30.0


@dataclass
class _InFlight:
    """Tracks a single outstanding GetBlock request."""

    hash_hex: str
    height: int
    peer_addr: str
    requested_at: float = field(default_factory=time.monotonic)


class BodySyncError(Exception):
    pass


class BodySync:
    """Download and validate full block bodies from the tip down to the horizon.

    Usage::

        body_sync = BodySync(adapter, peers, start_height=1, end_height=best_height)
        while not body_sync.is_complete():
            body_sync.check_run()
            time.sleep(0.5)

    Args:
        adapter:      ChainAdapter; its ``handle_block`` stores validated blocks.
        peers:        Live peer collection.
        start_height: First height needing a body (usually 1; genesis has no txs).
        end_height:   Last height to download (inclusive, typically best-header height).
    """

    def __init__(
        self,
        adapter: ChainAdapter,
        peers: PeerStore,
        start_height: int = 1,
        end_height: int = 0,
    ) -> None:
        self._adapter = adapter
        self._peers = peers
        self._start = start_height
        self._end = end_height

        # Heights still needing bodies, in ascending order
        self._pending: List[int] = list(range(start_height, end_height + 1))
        # Heights currently in-flight: height → _InFlight
        self._in_flight: Dict[int, _InFlight] = {}
        # Heights successfully stored
        self._done: Set[int] = set()

        self._last_log: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_complete(self) -> bool:
        """True when all blocks in the range have been fetched and validated."""
        return len(self._done) >= (self._end - self._start + 1)

    def progress(self) -> tuple[int, int]:
        """Return (done_count, total_count)."""
        total = max(0, self._end - self._start + 1)
        return len(self._done), total

    def check_run(self) -> bool:
        """Advance body sync by one step.  Returns True if work was done."""
        self._reclaim_stale()
        self._maybe_log_progress()

        if self.is_complete():
            return False

        # Choose up to BLOCK_REQUEST_BATCH_SIZE live peers
        live = self._peers.live().pick_n(BLOCK_REQUEST_BATCH_SIZE)
        if not live:
            log.debug("BodySync: no live peers")
            return False

        headroom = BLOCK_REQUEST_BATCH_SIZE - len(self._in_flight)
        if headroom <= 0:
            return True  # already at capacity

        # Identify heights to request: pending and not already in-flight
        to_request: List[int] = []
        for h in list(self._pending):
            if h not in self._in_flight and h not in self._done:
                to_request.append(h)
            if len(to_request) >= headroom:
                break

        if not to_request:
            return False

        peer_cycle = iter(live * ((len(to_request) // len(live)) + 1))
        for h in to_request:
            block_hash = self._adapter.get_block_hash_at_height(h)
            if block_hash is None:
                log.debug("BodySync: no header hash for height %d, skipping", h)
                self._pending.remove(h)
                self._done.add(h)  # treat as not needed
                continue

            peer: Peer = next(peer_cycle)
            peer.request_block(block_hash)
            self._in_flight[h] = _InFlight(
                hash_hex=block_hash.hex(),
                height=h,
                peer_addr=peer.addr,
            )
            log.debug(
                "BodySync: requested block h=%d hash=%s from %s",
                h,
                block_hash.hex()[:12],
                peer.addr,
            )

        return bool(to_request)

    def on_block_received(self, block_hash_hex: str) -> None:
        """Called by the adapter when a Block message is successfully stored.

        Marks the corresponding height as complete and removes it from
        in-flight tracking.
        """
        for h, req in list(self._in_flight.items()):
            if req.hash_hex == block_hash_hex:
                del self._in_flight[h]
                self._done.add(h)
                if h in self._pending:
                    self._pending.remove(h)
                log.debug("BodySync: completed h=%d hash=%s", h, block_hash_hex[:12])
                return

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _reclaim_stale(self) -> None:
        """Re-queue requests that have timed out."""
        now = time.monotonic()
        stale = [
            h
            for h, req in self._in_flight.items()
            if now - req.requested_at > BLOCK_REQUEST_TIMEOUT_SECS
        ]
        for h in stale:
            req = self._in_flight.pop(h)
            log.debug(
                "BodySync: stale request h=%d hash=%s from %s — re-queuing",
                h,
                req.hash_hex[:12],
                req.peer_addr,
            )
            # Re-add to front of pending if not already done
            if h not in self._done and h not in self._pending:
                self._pending.insert(0, h)

    def _maybe_log_progress(self) -> None:
        now = time.monotonic()
        if now - self._last_log < LOG_INTERVAL:
            return
        self._last_log = now
        done, total = self.progress()
        pct = (done / total * 100) if total > 0 else 0
        log.info(
            "BodySync: %d/%d blocks (%.1f%%) in_flight=%d pending=%d",
            done,
            total,
            pct,
            len(self._in_flight),
            len(self._pending),
        )
