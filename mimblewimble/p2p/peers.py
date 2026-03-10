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
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from mimblewimble.p2p.peer import Peer

# How often (seconds) to cull dead peers from the store
CULL_INTERVAL: float = 60.0


@dataclass(frozen=True)
class NodeRecord:
    """Persistable node metadata.

    This is intentionally small and backend-agnostic, so custom storage
    adapters can map it to SQL/NoSQL schemas as needed.
    """

    addr: str
    last_seen: float
    supports_pibd: bool
    supports_txhashset: bool
    total_difficulty: int

    @classmethod
    def from_peer(cls, peer: Peer) -> "NodeRecord":
        difficulty = getattr(peer.handshake, "genesis_block_difficulty", 0)
        return cls(
            addr=peer.addr,
            last_seen=peer.last_seen(),
            supports_pibd=peer.supports_pibd(),
            supports_txhashset=peer.supports_txhashset(),
            total_difficulty=int(difficulty),
        )


@dataclass(frozen=True)
class HeaderRecord:
    hash_hex: str
    height: int
    parent_hash_hex: str = ""
    total_difficulty: int = 0
    raw: bytes = b""


@dataclass(frozen=True)
class BlockRecord:
    hash_hex: str
    height: int = 0
    header_hash_hex: str = ""
    raw: bytes = b""


@dataclass(frozen=True)
class OutputRecord:
    commitment_hex: str
    block_hash_hex: str = ""
    height: int = 0
    status: str = ""
    raw: bytes = b""


class NodeStorage:
    """Storage adapter for known node metadata.

    Subclass this to persist node metadata in a custom backend
    (SQLite/Postgres/Redis/etc.), similar to wallet storage adapters.
    """

    def get_all_nodes(self) -> List[NodeRecord]:
        raise NotImplementedError

    def upsert_node(self, node: NodeRecord) -> None:
        raise NotImplementedError

    def remove_node(self, addr: str) -> None:
        raise NotImplementedError

    def store_headers(self, headers: List[HeaderRecord]) -> None:
        raise NotImplementedError

    def get_headers(self, limit: Optional[int] = None) -> List[HeaderRecord]:
        raise NotImplementedError

    def store_blocks(self, blocks: List[BlockRecord]) -> None:
        raise NotImplementedError

    def get_blocks(self, limit: Optional[int] = None) -> List[BlockRecord]:
        raise NotImplementedError

    def store_outputs(self, outputs: List[OutputRecord]) -> None:
        raise NotImplementedError

    def get_outputs(self, limit: Optional[int] = None) -> List[OutputRecord]:
        raise NotImplementedError

    def commit(self) -> None:
        pass


class NodeStorageInMemory(NodeStorage):
    """Default in-memory node storage adapter."""

    def __init__(self) -> None:
        self._nodes: Dict[str, NodeRecord] = {}
        self._headers: Dict[str, HeaderRecord] = {}
        self._blocks: Dict[str, BlockRecord] = {}
        self._outputs: Dict[str, OutputRecord] = {}

    def get_all_nodes(self) -> List[NodeRecord]:
        return list(self._nodes.values())

    def upsert_node(self, node: NodeRecord) -> None:
        self._nodes[node.addr] = node

    def remove_node(self, addr: str) -> None:
        self._nodes.pop(addr, None)

    def store_headers(self, headers: List[HeaderRecord]) -> None:
        for header in headers:
            self._headers[header.hash_hex] = header

    def get_headers(self, limit: Optional[int] = None) -> List[HeaderRecord]:
        values = sorted(self._headers.values(), key=lambda h: h.height, reverse=True)
        return values[:limit] if limit is not None else values

    def store_blocks(self, blocks: List[BlockRecord]) -> None:
        for block in blocks:
            self._blocks[block.hash_hex] = block

    def get_blocks(self, limit: Optional[int] = None) -> List[BlockRecord]:
        values = sorted(self._blocks.values(), key=lambda b: b.height, reverse=True)
        return values[:limit] if limit is not None else values

    def store_outputs(self, outputs: List[OutputRecord]) -> None:
        for output in outputs:
            self._outputs[output.commitment_hex] = output

    def get_outputs(self, limit: Optional[int] = None) -> List[OutputRecord]:
        values = sorted(self._outputs.values(), key=lambda o: o.height, reverse=True)
        return values[:limit] if limit is not None else values


class PeerStore:
    """Thread-safe collection of Peer objects with fluent query API.

    Usage::

        store = PeerStore()
        store.add(peer)
        best = store.live().pibd().highest_difficulty().pick()
    """

    def __init__(self, node_storage: Optional[NodeStorage] = None) -> None:
        self._peers: Dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._last_cull: float = time.monotonic()
        self._node_storage: NodeStorage = node_storage or NodeStorageInMemory()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, peer: Peer) -> None:
        """Register *peer* in the store."""
        with self._lock:
            self._peers[peer.addr] = peer
        self._node_storage.upsert_node(NodeRecord.from_peer(peer))
        self._node_storage.commit()

    def connect_outbound(
        self,
        addr: str,
        my_addr: str,
        genesis_hash: bytes,
        total_difficulty: int = 0,
        timeout: float = 30.0,
        adapter=None,
        start: bool = True,
        add: bool = True,
    ) -> Peer:
        """Connect and handshake with a peer, wiring this store automatically.

        This is the preferred constructor path for runtime peers to ensure
        ``Peer._dispatch`` has access to this ``PeerStore`` for persistence.
        """
        from mimblewimble.p2p.connection import Connection
        from mimblewimble.p2p.handshake import do_handshake_outbound

        conn = Connection.connect(addr, timeout=timeout)
        try:
            hs = do_handshake_outbound(
                conn,
                my_addr=my_addr,
                genesis_hash=genesis_hash,
                total_difficulty=total_difficulty,
            )
        except Exception:
            conn.close()
            raise

        peer = Peer(conn, hs, adapter=adapter, peer_store=self)
        if add:
            self.add(peer)
        if start:
            peer.start()
        return peer

    def remove(self, addr: str) -> None:
        """Remove the peer at *addr* (if present)."""
        with self._lock:
            self._peers.pop(addr, None)
        self._node_storage.remove_node(addr)
        self._node_storage.commit()

    def cull_dead(self) -> int:
        """Remove peers that are no longer alive.  Returns count removed."""
        with self._lock:
            dead = [addr for addr, p in self._peers.items() if not p.is_alive()]
            for addr in dead:
                del self._peers[addr]

        if dead:
            for addr in dead:
                self._node_storage.remove_node(addr)
            self._node_storage.commit()
        return len(dead)

    def known_nodes(self) -> List[NodeRecord]:
        """Return persistently stored node records."""
        return self._node_storage.get_all_nodes()

    def store_headers(self, headers: List[HeaderRecord]) -> None:
        self._node_storage.store_headers(headers)
        self._node_storage.commit()

    def get_headers(self, limit: Optional[int] = None) -> List[HeaderRecord]:
        return self._node_storage.get_headers(limit=limit)

    def store_blocks(self, blocks: List[BlockRecord]) -> None:
        self._node_storage.store_blocks(blocks)
        self._node_storage.commit()

    def get_blocks(self, limit: Optional[int] = None) -> List[BlockRecord]:
        return self._node_storage.get_blocks(limit=limit)

    def store_outputs(self, outputs: List[OutputRecord]) -> None:
        self._node_storage.store_outputs(outputs)
        self._node_storage.commit()

    def get_outputs(self, limit: Optional[int] = None) -> List[OutputRecord]:
        return self._node_storage.get_outputs(limit=limit)

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
