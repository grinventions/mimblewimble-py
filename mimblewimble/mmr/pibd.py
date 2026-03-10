"""
mimblewimble/mmr/pibd.py

PIBD sync state machine data structures.

Provides:
  SyncStatus     — enumeration of sync states for the node
  PIBDSegmentContainer — tracks an in-flight segment request
  SyncState      — mutable sync-state object threaded through the syncer

Mirrors Grin's servers/src/grin/sync/syncer.rs and
chain/src/txhashset/pibd_params.rs logic for state management.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set

from mimblewimble.mmr.pibd_params import SEGMENT_REQUEST_TIMEOUT_SECS
from mimblewimble.mmr.segment import SegmentTypeIdentifier

# ---------------------------------------------------------------------------
# SyncStatus
# ---------------------------------------------------------------------------


class SyncStatus(Enum):
    """High-level sync state of a Grin node.

    Values mirror the states tracked in Grin's ``SyncStatus`` enum
    (servers/src/grin/sync/syncer.rs).
    """

    #: Node is initializing; no sync decision made yet.
    INITIAL = auto()

    #: Waiting for enough peers to make sync decisions.
    AWAITING_PEERS = auto()

    #: Downloading and validating block headers only.
    HEADER_SYNC = auto()

    #: Downloading the TxHashSet snapshot ZIP from a peer.
    TXHASHSET_DOWNLOAD = auto()

    #: Validating a downloaded TxHashSet ZIP.
    TXHASHSET_VALIDATION = auto()

    #: Downloading PIBD segments (UTXO set) from peers.
    TXHASHSET_PIBD = auto()

    #: Processing individual block bodies.
    BODY_SYNC = auto()

    #: Node is fully synced.
    NO_SYNC = auto()


# ---------------------------------------------------------------------------
# PIBDSegmentContainer
# ---------------------------------------------------------------------------


@dataclass
class PIBDSegmentContainer:
    """Tracks a single in-flight PIBD segment request.

    Attributes:
        identifier      The segment type+identifier that was requested.
        peer_addr       The peer the request was sent to (host:port string).
        request_time    Monotonic timestamp (time.monotonic()) of the request.
    """

    identifier: SegmentTypeIdentifier
    peer_addr: str
    request_time: float = field(default_factory=time.monotonic)

    def is_stale(self) -> bool:
        """Return True if the request has exceeded the timeout threshold."""
        return (time.monotonic() - self.request_time) > SEGMENT_REQUEST_TIMEOUT_SECS

    def __repr__(self) -> str:
        age = time.monotonic() - self.request_time
        return (
            f"PIBDSegmentContainer({self.identifier!r}, "
            f"peer={self.peer_addr!r}, age={age:.1f}s)"
        )


# ---------------------------------------------------------------------------
# SyncState
# ---------------------------------------------------------------------------


class SyncState:
    """Mutable sync state shared between HeaderSync and StateSync.

    Thread safety: NOT thread-safe.  The syncer must serialize access.

    Key responsibilities:
      - Track the current :class:`SyncStatus`.
      - Maintain the set of in-flight PIBD segment requests with timeout
        detection.
      - Record download progress for log/UI reporting.
    """

    def __init__(self) -> None:
        self._status: SyncStatus = SyncStatus.INITIAL
        self._requested_segments: Dict[str, PIBDSegmentContainer] = {}
        # (downloaded_bytes, total_bytes) for snapshot download
        self._snapshot_progress: tuple[int, int] = (0, 0)
        # Count of PIBD segments applied so far
        self._pibd_applied: int = 0
        self._pibd_total: int = 0

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def status(self) -> SyncStatus:
        return self._status

    def update(self, new_status: SyncStatus) -> None:
        """Transition to *new_status*."""
        self._status = new_status

    def is_syncing(self) -> bool:
        """Return True if the node is not fully synced."""
        return self._status not in (SyncStatus.NO_SYNC, SyncStatus.INITIAL)

    # ------------------------------------------------------------------
    # PIBD segment tracking
    # ------------------------------------------------------------------

    def update_pibd_progress(self, applied: int, total: int) -> None:
        """Update PIBD segment progress counters."""
        self._pibd_applied = applied
        self._pibd_total = total

    def pibd_progress(self) -> tuple[int, int]:
        """Return (applied, total) PIBD segment counts."""
        return self._pibd_applied, self._pibd_total

    def add_pibd_segment_request(
        self,
        identifier: SegmentTypeIdentifier,
        peer_addr: str,
    ) -> None:
        """Record that a segment request was sent."""
        key = _segment_key(identifier)
        self._requested_segments[key] = PIBDSegmentContainer(
            identifier=identifier,
            peer_addr=peer_addr,
        )

    def remove_pibd_segment_request(
        self, identifier: SegmentTypeIdentifier
    ) -> Optional[PIBDSegmentContainer]:
        """Remove and return the container for *identifier* (if present)."""
        key = _segment_key(identifier)
        return self._requested_segments.pop(key, None)

    def remove_stale_pibd_requests(self) -> List[PIBDSegmentContainer]:
        """Remove and return all in-flight requests that have timed out.

        Callers typically re-request timed-out segments from a different peer.
        """
        stale = [c for c in self._requested_segments.values() if c.is_stale()]
        for c in stale:
            key = _segment_key(c.identifier)
            self._requested_segments.pop(key, None)
        return stale

    def clear_pibd_requests(self) -> None:
        """Remove ALL in-flight segment requests (used on peer change/reset)."""
        self._requested_segments.clear()

    def pending_segment_count(self) -> int:
        """Return the number of in-flight segment requests."""
        return len(self._requested_segments)

    def outstanding_peers(self) -> Set[str]:
        """Return the set of peers with pending requests."""
        return {c.peer_addr for c in self._requested_segments.values()}

    # ------------------------------------------------------------------
    # Snapshot download progress
    # ------------------------------------------------------------------

    def update_snapshot_download(self, downloaded: int, total: int) -> None:
        self._snapshot_progress = (downloaded, total)

    def snapshot_progress(self) -> tuple[int, int]:
        """Return (downloaded_bytes, total_bytes) for current snapshot."""
        return self._snapshot_progress

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"SyncState(status={self._status.name}, "
            f"in_flight={len(self._requested_segments)}, "
            f"pibd={self._pibd_applied}/{self._pibd_total})"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _segment_key(identifier: SegmentTypeIdentifier) -> str:
    """Return a string dict key for a SegmentTypeIdentifier."""
    return f"{identifier.segment_type.value}:{identifier.identifier.height}:{identifier.identifier.idx}"
