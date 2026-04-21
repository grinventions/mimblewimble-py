"""
mimblewimble/p2p/peer.py

Peer — represents a single connected Grin P2P peer.

Wraps a :class:`Connection` and provides typed send helpers used by the
header-sync and state-sync logic.  The receive loop is run on a background
thread per peer.

Reference: p2p/src/peer.rs
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Callable, List, Optional

from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.connection import Connection, ConnectionError
from mimblewimble.p2p.handshake import HandshakeResult, do_handshake_outbound

# Maximum number of peer addresses to send in a single PeerAddrs reply
MAX_PEER_ADDRS_RESPONSE = 20

from mimblewimble.p2p.message import (
    MessageType,
    MsgGetHeaders,
    MsgGetOutputBitmapSegment,
    MsgGetOutputSegment,
    MsgGetRangeProofSegment,
    MsgGetKernelSegment,
    MsgGetBlock,
    MsgGetCompactBlock,
    MsgCompactBlock,
    MsgGetPeerAddrs,
    MsgPeerAddrs,
    MsgPing,
    MsgTxHashSetRequest,
    MsgBanReason,
    MsgOutputBitmapSegment,
    MsgOutputSegment,
    MsgRangeProofSegment,
    MsgKernelSegment,
    MsgHeaders,
    MsgTxHashSetArchive,
    MAINNET_MAGIC,
)
from mimblewimble.mmr.segment import SegmentIdentifier

if TYPE_CHECKING:
    from mimblewimble.p2p.peers import PeerStore

log = logging.getLogger(__name__)

# How long to wait between Ping messages
PING_INTERVAL: float = 60.0
# How long without a message before declaring a peer dead
DEAD_TIMEOUT: float = 300.0


class PeerError(Exception):
    pass


class Peer:
    """A single connected P2P peer.

    Usage::

        conn = Connection.connect("127.0.0.1:13414")
        hs   = do_handshake_outbound(conn, my_addr="0.0.0.0:0",
                                     genesis_hash=GENESIS_HASH)
        peer = Peer(conn, hs, adapter=my_adapter)
        peer.start()          # launches receive loop thread
        peer.request_headers(locator)
        peer.stop()
    """

    def __init__(
        self,
        conn: Connection,
        handshake: HandshakeResult,
        adapter: Optional[ChainAdapter] = None,
        peer_store: Optional["PeerStore"] = None,
        on_new_peer_addr: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._conn = conn
        self.handshake = handshake
        self.addr = conn.peer_addr
        self._adapter = adapter
        self._peer_store = peer_store
        self._on_new_peer_addr = on_new_peer_addr
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_seen: float = time.monotonic()
        self._lock = threading.Lock()
        self.banned = False

    # ------------------------------------------------------------------
    # Life-cycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background receive-loop thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._receive_loop,
            name=f"peer-{self.addr}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the receive loop to exit and close the connection."""
        self._running = False
        self._conn.close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_alive(self) -> bool:
        return self._running and not self._conn.closed and not self.banned

    def supports_pibd(self) -> bool:
        return self.handshake.supports_pibd()

    def supports_txhashset(self) -> bool:
        return self.handshake.supports_txhashset()

    def last_seen(self) -> float:
        return self._last_seen

    # ------------------------------------------------------------------
    # Send helpers
    # ------------------------------------------------------------------

    def send_ping(self, total_difficulty: int = 0, height: int = 0) -> None:
        msg = MsgPing(total_difficulty=total_difficulty, height=height)
        self._send(msg.serialize())

    def request_headers(self, locator: List[bytes]) -> None:
        """Send a GetHeaders request with *locator* (list of known hashes)."""
        msg = MsgGetHeaders(locator=locator)
        self._send(msg.serialize())

    def request_txhashset(self, block_hash: bytes, height: int) -> None:
        """Request the TxHashSet ZIP archive at *block_hash*/*height*."""
        msg = MsgTxHashSetRequest(block_hash=block_hash, height=height)
        self._send(msg.serialize())

    def request_bitmap_segment(
        self, block_hash: bytes, identifier: SegmentIdentifier
    ) -> None:
        msg = MsgGetOutputBitmapSegment(block_hash=block_hash, identifier=identifier)
        self._send(msg.serialize())

    def request_output_segment(
        self, block_hash: bytes, identifier: SegmentIdentifier
    ) -> None:
        msg = MsgGetOutputSegment(block_hash=block_hash, identifier=identifier)
        self._send(msg.serialize())

    def request_rangeproof_segment(
        self, block_hash: bytes, identifier: SegmentIdentifier
    ) -> None:
        msg = MsgGetRangeProofSegment(block_hash=block_hash, identifier=identifier)
        self._send(msg.serialize())

    def request_kernel_segment(
        self, block_hash: bytes, identifier: SegmentIdentifier
    ) -> None:
        msg = MsgGetKernelSegment(block_hash=block_hash, identifier=identifier)
        self._send(msg.serialize())

    def request_block(self, block_hash: bytes) -> None:
        """Send a GetBlock request for *block_hash*."""
        msg = MsgGetBlock(block_hash=block_hash)
        self._send(msg.serialize())

    def request_compact_block(self, block_hash: bytes) -> None:
        """Send a GetCompactBlock request for *block_hash*."""
        msg = MsgGetCompactBlock(block_hash=block_hash)
        self._send(msg.serialize())

    def request_peer_addrs(self) -> None:
        """Send a GetPeerAddrs request to learn about more peers."""
        from mimblewimble.p2p.message import Capabilities

        msg = MsgGetPeerAddrs(capabilities=int(Capabilities.FULL_NODE))
        self._send(msg.serialize())

    def send_peer_addrs(self, peer_addrs) -> None:
        """Reply with a list of known peer addresses.

        Args:
            peer_addrs: List of :class:`~mimblewimble.p2p.message.PeerAddr`.
        """
        msg = MsgPeerAddrs(peers=peer_addrs)
        self._send(msg.serialize())

    def ban(self, reason: str = "") -> None:
        """Send a BanReason and close the connection."""
        try:
            msg = MsgBanReason(ban_reason=reason)
            self._send(msg.serialize())
        except Exception:
            pass
        self.banned = True
        self.stop()

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    def _receive_loop(self) -> None:
        """Background thread: read and dispatch incoming messages."""
        while self._running:
            try:
                msg_type, body = self._conn.recv_message()
            except ConnectionError as e:
                log.info("Peer %s disconnected: %s", self.addr, e)
                self._running = False
                break
            except Exception as e:
                log.warning("Peer %s recv error: %s", self.addr, e)
                self._running = False
                break

            self._last_seen = time.monotonic()
            self._dispatch(msg_type, body)

        self._conn.close()

    def _dispatch(self, msg_type: MessageType, body: bytes) -> None:
        """Route an incoming message to the adapter."""
        if self._adapter is None:
            return

        try:
            if msg_type == MessageType.Headers:
                msg = MsgHeaders.deserialize(body)
                from mimblewimble.p2p.header_sync import apply_headers_message

                apply_headers_message(
                    self._adapter,
                    msg.headers,
                    peer_addr=self.addr,
                    peers=self._peer_store,
                )

            elif msg_type == MessageType.TxHashSetArchive:
                msg = MsgTxHashSetArchive.deserialize(body)
                self._adapter.txhashset_write(msg.block_hash, msg.height, msg.zip_bytes)

            elif msg_type == MessageType.OutputBitmapSegment:
                msg = MsgOutputBitmapSegment.deserialize(body)
                if msg.segment is not None:
                    self._adapter.receive_bitmap_segment(msg.block_hash, msg.segment)

            elif msg_type == MessageType.OutputSegment:
                msg = MsgOutputSegment.deserialize(body)
                if msg.segment is not None:
                    self._adapter.receive_output_segment(msg.block_hash, msg.segment)

            elif msg_type == MessageType.RangeProofSegment:
                msg = MsgRangeProofSegment.deserialize(body)
                if msg.segment is not None:
                    self._adapter.receive_rangeproof_segment(
                        msg.block_hash, msg.segment
                    )

            elif msg_type == MessageType.KernelSegment:
                msg = MsgKernelSegment.deserialize(body)
                if msg.segment is not None:
                    self._adapter.receive_kernel_segment(msg.block_hash, msg.segment)

            elif msg_type == MessageType.Block:
                # The wire body is the raw serialised FullBlock bytes.
                # Pass the whole body; the adapter is responsible for deserialising.
                self._adapter.handle_block(b"", body)

            elif msg_type == MessageType.CompactBlock:
                self._adapter.handle_compact_block(body)

            elif msg_type == MessageType.Transaction:
                self._adapter.handle_transaction(body, from_stem=False)

            elif msg_type == MessageType.StemTransaction:
                self._adapter.handle_transaction(body, from_stem=True)

            elif msg_type == MessageType.BanReason:
                log.warning("Banned by peer %s", self.addr)
                self._running = False

            elif msg_type == MessageType.GetPeerAddrs:
                msg = MsgGetPeerAddrs.deserialize(body)
                self._handle_get_peer_addrs(msg)

            elif msg_type == MessageType.PeerAddrs:
                msg = MsgPeerAddrs.deserialize(body)
                self._handle_peer_addrs(msg)

            else:
                log.debug("Unhandled message %s from %s", msg_type.name, self.addr)

        except Exception as e:
            log.warning("Error dispatching %s from %s: %s", msg_type.name, self.addr, e)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send(self, data: bytes) -> None:
        with self._lock:
            try:
                self._conn.send_raw(data)
            except ConnectionError as e:
                log.warning("Send to %s failed: %s", self.addr, e)
                self._running = False

    def _handle_get_peer_addrs(self, msg: MsgGetPeerAddrs) -> None:
        """Reply to a GetPeerAddrs request with locally known peers."""
        if self._peer_store is None:
            return
        from mimblewimble.p2p.message import PeerAddr

        try:
            live_peers = self._peer_store.live().pick_n(MAX_PEER_ADDRS_RESPONSE)
        except Exception:
            return
        addrs = []
        for p in live_peers:
            if p.addr == self.addr:
                continue  # don't reflect the requesting peer back to itself
            addrs.append(PeerAddr(addr=p.addr))
        if addrs:
            self.send_peer_addrs(addrs)

    def _handle_peer_addrs(self, msg: MsgPeerAddrs) -> None:
        """Process a PeerAddrs reply — attempt to connect to unknown peers."""
        for pa in msg.peers:
            addr = pa.addr
            if self._peer_store is not None:
                known = self._peer_store.all()
                if any(p.addr == addr for p in known):
                    continue
            log.info("Peer discovery: new candidate %s from %s", addr, self.addr)
            if self._on_new_peer_addr is not None:
                try:
                    self._on_new_peer_addr(addr)
                except Exception as exc:
                    log.debug("on_new_peer_addr(%s) error: %s", addr, exc)

    def __repr__(self) -> str:
        return (
            f"Peer(addr={self.addr!r}, alive={self.is_alive()}, "
            f"pibd={self.supports_pibd()})"
        )
