import socket
import struct

import pytest

from mimblewimble.p2p.connection import Connection, ConnectionError, MAX_BODY_BYTES
from mimblewimble.p2p.message import MAINNET_MAGIC, MessageType, pack_header


def _socket_pair_connection():
    left, right = socket.socketpair()
    conn = Connection.from_socket(left, peer_addr="local-test", magic=MAINNET_MAGIC)
    return conn, right


def test_recv_message_nonblocking_waits_for_complete_frame():
    conn, peer = _socket_pair_connection()
    try:
        frame = pack_header(MessageType.Ping, b"")
        peer.sendall(frame[:6])
        assert conn.recv_message_nonblocking() is None

        peer.sendall(frame[6:])
        message = conn.recv_message_nonblocking()
        assert message is not None
        msg_type, body = message
        assert msg_type == MessageType.Ping
        assert body == b""
    finally:
        conn.close()
        peer.close()


def test_recv_message_nonblocking_rejects_magic_mismatch():
    conn, peer = _socket_pair_connection()
    try:
        bad_magic = bytes([0x83, 0xC1])
        peer.sendall(pack_header(MessageType.Ping, b"", magic=bad_magic))

        with pytest.raises(ConnectionError, match="Magic mismatch"):
            conn.recv_message_nonblocking()
    finally:
        conn.close()
        peer.close()


def test_recv_message_nonblocking_rejects_oversized_body_length():
    conn, peer = _socket_pair_connection()
    try:
        header = MAINNET_MAGIC + struct.pack(
            "<IQ", int(MessageType.Ping), MAX_BODY_BYTES + 1
        )
        peer.sendall(header)

        with pytest.raises(ConnectionError, match="Body too large"):
            conn.recv_message_nonblocking()
    finally:
        conn.close()
        peer.close()


def test_recv_message_nonblocking_rejects_invalid_message_type():
    conn, peer = _socket_pair_connection()
    try:
        header = MAINNET_MAGIC + struct.pack("<IQ", 9999, 0)
        peer.sendall(header)

        with pytest.raises(ConnectionError, match="Invalid message header"):
            conn.recv_message_nonblocking()
    finally:
        conn.close()
        peer.close()
