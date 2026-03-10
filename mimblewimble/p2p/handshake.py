"""
mimblewimble/p2p/handshake.py

Grin P2P Hand / Shake handshake.

The connecting peer sends Hand; the accepting peer responds with Shake.
Both peers then know each other's:
  - Protocol version
  - Capabilities
  - Node user-agent
  - Genesis block hash (used to detect mainnet/testnet mismatches)

Reference: p2p/src/handshake.rs
"""

from __future__ import annotations

import logging
import os
import struct

from mimblewimble.p2p.connection import Connection, ConnectionError
from mimblewimble.p2p.message import (
    Capabilities,
    MessageType,
    MsgHand,
    MsgShake,
    PROTOCOL_VERSION,
    USER_AGENT,
)

log = logging.getLogger(__name__)


class HandshakeError(Exception):
    """Raised when the handshake fails (version mismatch, wrong genesis, etc.)."""


class HandshakeResult:
    """Outcome of a completed handshake."""

    def __init__(
        self,
        version: int,
        capabilities: int,
        user_agent: str,
        genesis_hash: bytes,
        peer_addr: str,
        nonce: int,
    ) -> None:
        self.version = version
        self.capabilities = capabilities
        self.user_agent = user_agent
        self.genesis_hash = genesis_hash
        self.peer_addr = peer_addr
        self.nonce = nonce

    def supports_pibd(self) -> bool:
        return bool(self.capabilities & int(Capabilities.PIBD_HIST))

    def supports_txhashset(self) -> bool:
        return bool(self.capabilities & int(Capabilities.TXHASHSET_HIST))

    def __repr__(self) -> str:
        return (
            f"HandshakeResult(ver={self.version}, peer={self.peer_addr!r}, "
            f"pibd={self.supports_pibd()}, agent={self.user_agent!r})"
        )


# ---------------------------------------------------------------------------
# Outbound handshake (we are the initiating peer)
# ---------------------------------------------------------------------------


def do_handshake_outbound(
    conn: Connection,
    my_addr: str,
    genesis_hash: bytes,
    total_difficulty: int = 0,
) -> HandshakeResult:
    """Send Hand and wait for Shake.

    Args:
        conn            Open :class:`Connection` to the remote peer.
        my_addr         Our externally reachable address (``"host:port"``).
        genesis_hash    32-byte genesis block hash (mainnet or testnet).
        total_difficulty Our current total chain difficulty.

    Returns:
        :class:`HandshakeResult` populated from the received Shake.

    Raises:
        HandshakeError on protocol / version mismatch.
    """
    nonce = struct.unpack("<Q", os.urandom(8))[0]

    hand = MsgHand(
        version=PROTOCOL_VERSION,
        capabilities=int(Capabilities.FULL_NODE),
        nonce=nonce,
        genesis_block_difficulty=total_difficulty,
        sender_addr=my_addr,
        receiver_addr=conn.peer_addr,
        user_agent=USER_AGENT,
        genesis_hash=genesis_hash,
    )
    conn.send_raw(hand.serialize())
    log.debug("Sent Hand to %s (nonce=%d)", conn.peer_addr, nonce)

    msg_type, body = conn.recv_message()
    if msg_type != MessageType.Shake:
        raise HandshakeError(
            f"Expected Shake, got {msg_type.name} from {conn.peer_addr}"
        )

    shake = MsgShake.deserialize(body)
    _validate_genesis(shake.genesis_hash, genesis_hash, conn.peer_addr)
    _validate_version(shake.version, conn.peer_addr)

    log.info(
        "Handshake complete with %s (ver=%d, pibd=%s)",
        conn.peer_addr,
        shake.version,
        bool(shake.capabilities & int(Capabilities.PIBD_HIST)),
    )
    return HandshakeResult(
        version=shake.version,
        capabilities=shake.capabilities,
        user_agent=shake.user_agent,
        genesis_hash=shake.genesis_hash,
        peer_addr=conn.peer_addr,
        nonce=shake.nonce,
    )


# ---------------------------------------------------------------------------
# Inbound handshake (we are the accepting peer)
# ---------------------------------------------------------------------------


def do_handshake_inbound(
    conn: Connection,
    my_addr: str,
    genesis_hash: bytes,
    total_difficulty: int = 0,
) -> HandshakeResult:
    """Wait for Hand then send Shake.

    Returns:
        :class:`HandshakeResult` populated from the received Hand.

    Raises:
        HandshakeError on protocol / version mismatch.
    """
    msg_type, body = conn.recv_message()
    if msg_type != MessageType.Hand:
        raise HandshakeError(
            f"Expected Hand, got {msg_type.name} from {conn.peer_addr}"
        )

    hand = MsgHand.deserialize(body)
    _validate_genesis(hand.genesis_hash, genesis_hash, conn.peer_addr)
    _validate_version(hand.version, conn.peer_addr)

    nonce = struct.unpack("<Q", os.urandom(8))[0]
    shake = MsgShake(
        version=PROTOCOL_VERSION,
        capabilities=int(Capabilities.FULL_NODE),
        nonce=nonce,
        genesis_block_difficulty=total_difficulty,
        receiver_addr=hand.sender_addr,
        user_agent=USER_AGENT,
        genesis_hash=genesis_hash,
    )
    conn.send_raw(shake.serialize())
    log.debug("Sent Shake to %s", conn.peer_addr)

    return HandshakeResult(
        version=hand.version,
        capabilities=hand.capabilities,
        user_agent=hand.user_agent,
        genesis_hash=hand.genesis_hash,
        peer_addr=conn.peer_addr,
        nonce=hand.nonce,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_genesis(peer_genesis: bytes, our_genesis: bytes, addr: str) -> None:
    if peer_genesis != our_genesis:
        raise HandshakeError(
            f"Genesis mismatch with {addr}: "
            f"peer={peer_genesis.hex()!r} us={our_genesis.hex()!r}"
        )


def _validate_version(peer_version: int, addr: str) -> None:
    if peer_version < 1:
        raise HandshakeError(
            f"Peer {addr} has unsupported protocol version {peer_version}"
        )
