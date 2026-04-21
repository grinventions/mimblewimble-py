"""
mimblewimble/p2p/message.py

Grin P2P wire protocol message types and serialisation.

Message frame:
    2 bytes  magic          [0x61, 0x3d] on mainnet
    4 bytes  msg_type       LE uint32 (MessageType enum value)
    8 bytes  body_len       LE uint64

All integers are little-endian unless noted.  Strings are 4-byte LE
length-prefixed UTF-8.

Reference: p2p/src/msg.rs in the Grin repository.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Tuple

from mimblewimble.mmr.segment import (
    Segment,
    SegmentIdentifier,
    SegmentType,
    SegmentTypeIdentifier,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAINNET_MAGIC: bytes = bytes([0x61, 0x3D])
TESTNET_MAGIC: bytes = bytes([0x83, 0xC1])
HEADER_LEN: int = 2 + 4 + 8  # magic(2) + type(4) + body_len(8)

# Current protocol version advertised in Hand/Shake
PROTOCOL_VERSION: int = 1

# User-agent string
USER_AGENT: str = "MW/mimblewimble-py/0.1.0"

# Maximum number of headers in a single Headers message
MAX_HEADERS: int = 512

# Maximum number of peer addresses in PeerAddrs
MAX_PEER_ADDRS: int = 256


# ---------------------------------------------------------------------------
# MessageType
# ---------------------------------------------------------------------------


class MessageType(IntEnum):
    """Grin P2P message type codes, matching Grin's ``Type`` enum in msg.rs."""

    Error = 0
    Hand = 1
    Shake = 2
    Ping = 3
    Pong = 4
    GetPeerAddrs = 5
    PeerAddrs = 6
    GetHeaders = 7
    Headers = 8
    GetBlock = 9
    Block = 10
    GetCompactBlock = 11
    CompactBlock = 12
    StemTransaction = 13
    Transaction = 14
    TxHashSetRequest = 15
    TxHashSetArchive = 16
    BanReason = 17
    GetTransactionKernel = 18
    TransactionKernel = 19
    KernelDataRequest = 20
    KernelDataResponse = 21
    GetOutputBitmapSegment = 22
    OutputBitmapSegment = 23
    GetOutputSegment = 24
    OutputSegment = 25
    GetRangeProofSegment = 26
    RangeProofSegment = 27
    GetKernelSegment = 28
    KernelSegment = 29


# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------


def pack_header(
    msg_type: MessageType, body: bytes, magic: bytes = MAINNET_MAGIC
) -> bytes:
    """Prepend the 14-byte frame header to *body*."""
    return magic + struct.pack("<IQ", int(msg_type), len(body)) + body


def unpack_header(data: bytes) -> Tuple[bytes, MessageType, int]:
    """Parse the 14-byte frame header.

    Returns:
        (magic, msg_type, body_len)
    Raises:
        ValueError if the header is malformed.
    """
    if len(data) < HEADER_LEN:
        raise ValueError(f"Header too short: {len(data)} < {HEADER_LEN}")
    magic = data[:2]
    msg_type, body_len = struct.unpack_from("<IQ", data, 2)
    return magic, MessageType(msg_type), body_len


# ---------------------------------------------------------------------------
# Low-level encode/decode helpers
# ---------------------------------------------------------------------------


def _encode_str(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack("<I", len(encoded)) + encoded


def _decode_str(data: bytes, offset: int) -> Tuple[str, int]:
    (length,) = struct.unpack_from("<I", data, offset)
    offset += 4
    return data[offset : offset + length].decode("utf-8"), offset + length


def _encode_bytes(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _decode_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    (length,) = struct.unpack_from("<I", data, offset)
    offset += 4
    return data[offset : offset + length], offset + length


# ---------------------------------------------------------------------------
# Peer address
# ---------------------------------------------------------------------------


@dataclass
class PeerAddr:
    """Single peer address (host:port) as used in PeerAddrs messages."""

    addr: str  # "host:port"

    def serialize(self) -> bytes:
        return _encode_str(self.addr)

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple["PeerAddr", int]:
        addr, offset = _decode_str(data, offset)
        return cls(addr=addr), offset


# ---------------------------------------------------------------------------
# Capabilities flags
# ---------------------------------------------------------------------------


class Capabilities(IntEnum):
    """Bitmask of peer capabilities (Grin's Capabilities struct in p2p/src/types.rs)."""

    UNKNOWN = 0
    FULL_HIST = 1 << 0
    TXHASHSET_HIST = 1 << 1
    PEER_LIST = 1 << 2
    TX_KERNEL_HASH = 1 << 3
    PIBD_HIST = 1 << 4
    PIBD_HIST_1 = 1 << 5
    PIBD_HIST_2 = 1 << 6

    # Convenience alias
    FULL_NODE = FULL_HIST | TXHASHSET_HIST | PEER_LIST | TX_KERNEL_HASH | PIBD_HIST


# ---------------------------------------------------------------------------
# Message classes
# ---------------------------------------------------------------------------


@dataclass
class MsgError:
    """Error message."""

    msg_type = MessageType.Error
    message: str = ""

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, _encode_str(self.message))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgError":
        message, _ = _decode_str(body, 0)
        return cls(message=message)


@dataclass
class MsgHand:
    """Hand — initial handshake message sent by the connecting peer.

    Wire body (all LE):
        4   version       uint32  protocol version
        4   capabilities  uint32  bitmask
        8   nonce         uint64  random nonce to detect self-connections
        8   genesis_block_difficulty uint64
        N   sender_addr   length-prefixed string "host:port"
        N   receiver_addr length-prefixed string "host:port"
        N   user_agent    length-prefixed string
        32  genesis_hash  bytes
    """

    msg_type = MessageType.Hand
    version: int = PROTOCOL_VERSION
    capabilities: int = int(Capabilities.FULL_NODE)
    nonce: int = 0
    genesis_block_difficulty: int = 0
    sender_addr: str = ""
    receiver_addr: str = ""
    user_agent: str = USER_AGENT
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        body = struct.pack(
            "<IIQQ",
            self.version,
            self.capabilities,
            self.nonce,
            self.genesis_block_difficulty,
        )
        body += _encode_str(self.sender_addr)
        body += _encode_str(self.receiver_addr)
        body += _encode_str(self.user_agent)
        body += self.genesis_hash[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgHand":
        version, capabilities, nonce, genesis_block_difficulty = struct.unpack_from(
            "<IIQQ", body, 0
        )
        offset = 4 + 4 + 8 + 8
        sender_addr, offset = _decode_str(body, offset)
        receiver_addr, offset = _decode_str(body, offset)
        user_agent, offset = _decode_str(body, offset)
        genesis_hash = body[offset : offset + 32]
        return cls(
            version=version,
            capabilities=capabilities,
            nonce=nonce,
            genesis_block_difficulty=genesis_block_difficulty,
            sender_addr=sender_addr,
            receiver_addr=receiver_addr,
            user_agent=user_agent,
            genesis_hash=genesis_hash,
        )


@dataclass
class MsgShake:
    """Shake — handshake response.

    Same wire format as Hand but without sender_addr.
    """

    msg_type = MessageType.Shake
    version: int = PROTOCOL_VERSION
    capabilities: int = int(Capabilities.FULL_NODE)
    nonce: int = 0
    genesis_block_difficulty: int = 0
    receiver_addr: str = ""
    user_agent: str = USER_AGENT
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        body = struct.pack(
            "<IIQQ",
            self.version,
            self.capabilities,
            self.nonce,
            self.genesis_block_difficulty,
        )
        body += _encode_str(self.receiver_addr)
        body += _encode_str(self.user_agent)
        body += self.genesis_hash[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgShake":
        version, capabilities, nonce, genesis_block_difficulty = struct.unpack_from(
            "<IIQQ", body, 0
        )
        offset = 4 + 4 + 8 + 8
        receiver_addr, offset = _decode_str(body, offset)
        user_agent, offset = _decode_str(body, offset)
        genesis_hash = body[offset : offset + 32]
        return cls(
            version=version,
            capabilities=capabilities,
            nonce=nonce,
            genesis_block_difficulty=genesis_block_difficulty,
            receiver_addr=receiver_addr,
            user_agent=user_agent,
            genesis_hash=genesis_hash,
        )


@dataclass
class MsgPing:
    """Ping — keepalive with the sender's known total difficulty."""

    msg_type = MessageType.Ping
    total_difficulty: int = 0
    height: int = 0

    def serialize(self) -> bytes:
        body = struct.pack("<QQ", self.total_difficulty, self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPing":
        total_difficulty, height = struct.unpack_from("<QQ", body)
        return cls(total_difficulty=total_difficulty, height=height)


@dataclass
class MsgPong:
    """Pong — response to Ping."""

    msg_type = MessageType.Pong
    total_difficulty: int = 0
    height: int = 0

    def serialize(self) -> bytes:
        body = struct.pack("<QQ", self.total_difficulty, self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPong":
        total_difficulty, height = struct.unpack_from("<QQ", body)
        return cls(total_difficulty=total_difficulty, height=height)


@dataclass
class MsgGetPeerAddrs:
    """Request peer addresses from a peer."""

    msg_type = MessageType.GetPeerAddrs
    capabilities: int = int(Capabilities.FULL_NODE)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, struct.pack("<I", self.capabilities))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetPeerAddrs":
        (capabilities,) = struct.unpack_from("<I", body)
        return cls(capabilities=capabilities)


@dataclass
class MsgPeerAddrs:
    """List of peer addresses."""

    msg_type = MessageType.PeerAddrs
    peers: List[PeerAddr] = field(default_factory=list)

    def serialize(self) -> bytes:
        body = struct.pack("<I", len(self.peers))
        for p in self.peers:
            body += p.serialize()
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPeerAddrs":
        (n,) = struct.unpack_from("<I", body)
        offset = 4
        peers = []
        for _ in range(min(n, MAX_PEER_ADDRS)):
            peer, offset = PeerAddr.deserialize(body, offset)
            peers.append(peer)
        return cls(peers=peers)


@dataclass
class MsgGetHeaders:
    """Request block headers using a locator (list of known header hashes)."""

    msg_type = MessageType.GetHeaders
    locator: List[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        body = struct.pack("<I", len(self.locator))
        for h in self.locator:
            body += h[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetHeaders":
        (n,) = struct.unpack_from("<I", body)
        offset = 4
        locator = []
        for _ in range(n):
            locator.append(body[offset : offset + 32])
            offset += 32
        return cls(locator=locator)


@dataclass
class MsgHeaders:
    """Response containing serialised block headers."""

    msg_type = MessageType.Headers
    # Each entry is the raw serialised bytes of a BlockHeader
    headers: List[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        body = struct.pack("<I", len(self.headers))
        for h in self.headers:
            body += struct.pack("<I", len(h)) + h
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgHeaders":
        (n,) = struct.unpack_from("<I", body)
        offset = 4
        headers = []
        for _ in range(min(n, MAX_HEADERS)):
            (hlen,) = struct.unpack_from("<I", body, offset)
            offset += 4
            headers.append(body[offset : offset + hlen])
            offset += hlen
        return cls(headers=headers)


@dataclass
class MsgGetBlock:
    """Request a full block by hash."""

    msg_type = MessageType.GetBlock
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetBlock":
        return cls(block_hash=body[:32])


@dataclass
class MsgGetCompactBlock:
    """Request a compact block by hash."""

    msg_type = MessageType.GetCompactBlock
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetCompactBlock":
        return cls(block_hash=body[:32])


@dataclass
class MsgTxHashSetRequest:
    """Request a TxHashSet ZIP archive at a block hash/height.

    Wire body:
        32 bytes  block_hash
        8  bytes  LE height
    """

    msg_type = MessageType.TxHashSetRequest
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    height: int = 0

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00") + struct.pack("<Q", self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgTxHashSetRequest":
        block_hash = body[:32]
        (height,) = struct.unpack_from("<Q", body, 32)
        return cls(block_hash=block_hash, height=height)


@dataclass
class MsgTxHashSetArchive:
    """Response with TxHashSet ZIP bytes (streamed as body bytes).

    Wire body:
        32 bytes  block_hash
        8  bytes  LE height
        8  bytes  LE bytes_len  (length of following ZIP bytes)
        bytes_len bytes  zip data
    """

    msg_type = MessageType.TxHashSetArchive
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    height: int = 0
    zip_bytes: bytes = b""

    def serialize(self) -> bytes:
        body = (
            self.block_hash[:32].ljust(32, b"\x00")
            + struct.pack("<QQ", self.height, len(self.zip_bytes))
            + self.zip_bytes
        )
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgTxHashSetArchive":
        block_hash = body[:32]
        height, bytes_len = struct.unpack_from("<QQ", body, 32)
        zip_bytes = body[32 + 16 : 32 + 16 + bytes_len]
        return cls(block_hash=block_hash, height=height, zip_bytes=zip_bytes)


@dataclass
class MsgBanReason:
    """Sent just before disconnecting a banned peer."""

    msg_type = MessageType.BanReason
    ban_reason: str = ""

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, _encode_str(self.ban_reason))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgBanReason":
        message, _ = _decode_str(body, 0)
        return cls(ban_reason=message)


# ---------------------------------------------------------------------------
# PIBD segment request / response messages
# ---------------------------------------------------------------------------


@dataclass
class MsgGetOutputBitmapSegment:
    """Request a bitmap segment."""

    msg_type = MessageType.GetOutputBitmapSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00")
        if self.identifier is not None:
            body += self.identifier.serialize()
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetOutputBitmapSegment":
        block_hash = body[:32]
        identifier = None
        if len(body) >= 32 + 9:
            identifier = SegmentIdentifier.deserialize(body[32 : 32 + 9])
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgOutputBitmapSegment:
    """A bitmap segment response."""

    msg_type = MessageType.OutputBitmapSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00")
        if self.segment is not None:
            seg_bytes = self.segment.serialize()
            body += struct.pack("<I", len(seg_bytes)) + seg_bytes
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgOutputBitmapSegment":
        block_hash = body[:32]
        segment = None
        if len(body) > 32 + 4:
            (seg_len,) = struct.unpack_from("<I", body, 32)
            if seg_len > 0:
                segment = Segment.deserialize(body[36 : 36 + seg_len])
        return cls(block_hash=block_hash, segment=segment)


def _make_get_segment_msg(
    msg_type: MessageType, block_hash: bytes, identifier: SegmentIdentifier
) -> bytes:
    """Helper to build a GetXxxSegment body."""
    body = block_hash[:32].ljust(32, b"\x00") + identifier.serialize()
    return pack_header(msg_type, body)


def _parse_get_segment_body(body: bytes) -> Tuple[bytes, SegmentIdentifier]:
    """Parse a GetXxxSegment body: 32-byte hash + 9-byte SegmentIdentifier."""
    block_hash = body[:32]
    identifier = SegmentIdentifier.deserialize(body[32 : 32 + 9])
    return block_hash, identifier


def _make_segment_response(
    msg_type: MessageType, block_hash: bytes, segment: Segment
) -> bytes:
    """Helper to build a XxxSegment response body."""
    seg_bytes = segment.serialize()
    body = (
        block_hash[:32].ljust(32, b"\x00")
        + struct.pack("<I", len(seg_bytes))
        + seg_bytes
    )
    return pack_header(msg_type, body)


def _parse_segment_response(body: bytes) -> Tuple[bytes, Segment]:
    """Parse a XxxSegment response body."""
    block_hash = body[:32]
    (seg_len,) = struct.unpack_from("<I", body, 32)
    segment = Segment.deserialize(body[36 : 36 + seg_len])
    return block_hash, segment


@dataclass
class MsgGetOutputSegment:
    """Request an output PMMR segment."""

    msg_type = MessageType.GetOutputSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetOutputSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgOutputSegment:
    """Output PMMR segment response."""

    msg_type = MessageType.OutputSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgOutputSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


@dataclass
class MsgGetRangeProofSegment:
    """Request a rangeproof PMMR segment."""

    msg_type = MessageType.GetRangeProofSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetRangeProofSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgRangeProofSegment:
    """Rangeproof PMMR segment response."""

    msg_type = MessageType.RangeProofSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgRangeProofSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


@dataclass
class MsgGetKernelSegment:
    """Request a kernel MMR segment."""

    msg_type = MessageType.GetKernelSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetKernelSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgKernelSegment:
    """Kernel MMR segment response."""

    msg_type = MessageType.KernelSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgKernelSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


# ---------------------------------------------------------------------------
# Compact block
# ---------------------------------------------------------------------------


@dataclass
class MsgCompactBlock:
    """A compact block sent in response to ``GetCompactBlock``.

    Wire body (all LE):
        [BlockHeader bytes]
        8  bytes  nonce            uint64
        2  bytes  num_full_outputs uint16
        2  bytes  num_full_kernels uint16
        2  bytes  num_short_ids    uint16
        [full output bytes] * num_full_outputs
        [full kernel bytes] * num_full_kernels
        [6-byte short-id]  * num_short_ids

    Note: Full output/kernel parsing requires the serializer layer from
    ``mimblewimble.blockchain`` and is therefore done lazily on access.
    """

    msg_type = MessageType.CompactBlock
    # Raw body bytes — header + nonce + short-IDs; parsed on demand.
    raw_body: bytes = field(default_factory=bytes)
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.raw_body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgCompactBlock":
        # The block hash is not transmitted separately; callers should compute
        # it from the header inside raw_body if needed.
        return cls(raw_body=body, block_hash=b"\x00" * 32)
