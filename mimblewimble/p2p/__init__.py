"""
mimblewimble/p2p/__init__.py

Grin P2P networking for mimblewimble-py.

Public surface::

    from mimblewimble.p2p import (
        Connection, Peer, PeerStore, PeerQuery,
        ChainAdapter, NoopChainAdapter,
        MessageType, Capabilities,
        do_handshake_outbound, do_handshake_inbound,
    )
"""

from mimblewimble.p2p.adapter import ChainAdapter, NoopChainAdapter
from mimblewimble.p2p.connection import Connection
from mimblewimble.p2p.handshake import (
    HandshakeError,
    HandshakeResult,
    do_handshake_inbound,
    do_handshake_outbound,
)
from mimblewimble.p2p.message import Capabilities, MessageType
from mimblewimble.p2p.peer import Peer
from mimblewimble.p2p.peers import PeerStore, PeerQuery

__all__ = [
    "ChainAdapter",
    "Capabilities",
    "Connection",
    "HandshakeError",
    "HandshakeResult",
    "MessageType",
    "NoopChainAdapter",
    "Peer",
    "PeerQuery",
    "PeerStore",
    "do_handshake_inbound",
    "do_handshake_outbound",
]
