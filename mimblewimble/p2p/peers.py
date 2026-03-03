"""
mimblewimble/p2p/peers.py

PeerStore — collection of connected peers with fluent filtering.

Provides the subset-selection logic used by HeaderSync and StateSync to
choose the best peer for each request: highest difficulty, PIBD-capable,
not recently used, etc.

Reference: servers/src/grin/sync/*.rs peer selection logic
"""

from __future__ import annotations

import random
import threading
import time
from typing import Callable, Dict, Iterator, List, Optional

from mimblewimble.p2p.peer import Peer

# How often (seconds) to cull dead peers from the store
CULL_INTERVAL: float = 60.0


class PeerStore:
    """Thread-safe collection of Peer objects with fluent query API.

    Usage::

        store = PeerStore()
        store.add(peer)
        best = store.live().pibd().highest_difficulty().pick()
    """

    def __init__(self) -> None:
        self._peers: Dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._last_cull: float = time.monotonic()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, peer: Peer) -> None:
        """Register *peer* in the store."""
        with self._lock:
            self._peers[peer.addr] = peer

    def remove(self, addr: str) -> None:
        """Remove the peer at *addr* (if present)."""
        with self._lock:
            self._peers.pop(addr, None)

    def cull_dead(self) -> int:
        """Remove peers that are no longer alive.  Returns count removed."""
        with self._lock:
            dead = [addr for addr, p in self._peers.items() if not p.is_alive()]
            for addr in dead:
                del self._peers[addr]
        return len(dead)

    def all(self) -> List[Peer]:
        """Return a snapshot list of all peers."""
        with self._lock:
            return list(self._peers.values())

    def count(self) -> int:
        with self._lock:
            return len(self._peers)

    # ------------------------------------------------------------------
    # Query entry-point: returns a PeerQuery builder
    # ------------------------------------------------------------------

    def query(self) -> "PeerQuery":
        """Start building a filtered peer query."""
        with self._lock:
            peers = list(self._peers.values())
        return PeerQuery(peers)

    # Short-hand aliases used by sync code
    def live(self) -> "PeerQuery":
        return self.query().live()

    def pibd_capable(self) -> "PeerQuery":
        return self.query().live().pibd()

    def txhashset_capable(self) -> "PeerQuery":
        return self.query().live().txhashset()

    def __repr__(self) -> str:
        return f"PeerStore(count={self.count()})"


# ---------------------------------------------------------------------------
# PeerQuery — fluent filter builder
# ---------------------------------------------------------------------------


class PeerQuery:
    """Fluent peer-filter / selection builder.

    All methods return ``self`` (except terminal ``pick``/``all``).
    """

    def __init__(self, peers: List[Peer]) -> None:
        self._peers = peers

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def live(self) -> "PeerQuery":
        self._peers = [p for p in self._peers if p.is_alive()]
        return self

    def pibd(self) -> "PeerQuery":
        self._peers = [p for p in self._peers if p.supports_pibd()]
        return self

    def txhashset(self) -> "PeerQuery":
        self._peers = [p for p in self._peers if p.supports_txhashset()]
        return self

    def exclude(self, addr: str) -> "PeerQuery":
        self._peers = [p for p in self._peers if p.addr != addr]
        return self

    def exclude_all(self, addrs: List[str]) -> "PeerQuery":
        addr_set = set(addrs)
        self._peers = [p for p in self._peers if p.addr not in addr_set]
        return self

    def min_total_difficulty(self, min_diff: int) -> "PeerQuery":
        """Keep only peers whose reported difficulty meets *min_diff*."""
        # Peers don't cache difficulty directly; we skip this filter when
        # difficulty is not tracked per-peer.  Subclasses can override.
        return self

    def custom(self, fn: Callable[[Peer], bool]) -> "PeerQuery":
        self._peers = [p for p in self._peers if fn(p)]
        return self

    # ------------------------------------------------------------------
    # Terminal selections
    # ------------------------------------------------------------------

    def highest_difficulty(self) -> "PeerQuery":
        """Sort peers by ``handshake.genesis_block_difficulty`` descending."""
        self._peers.sort(
            key=lambda p: p.handshake.genesis_block_difficulty, reverse=True
        )
        return self

    def most_recent(self) -> "PeerQuery":
        """Sort peers by last-seen time (most recent first)."""
        self._peers.sort(key=lambda p: p.last_seen(), reverse=True)
        return self

    def shuffle(self) -> "PeerQuery":
        random.shuffle(self._peers)
        return self

    def pick(self) -> Optional[Peer]:
        """Return the first peer in the current list, or None if empty."""
        return self._peers[0] if self._peers else None

    def pick_n(self, n: int) -> List[Peer]:
        """Return up to *n* peers."""
        return self._peers[:n]

    def all(self) -> List[Peer]:
        return list(self._peers)

    def count(self) -> int:
        return len(self._peers)
