import socket
import struct
import threading

import pytest

from mimblewimble.p2p.connection import Connection, ConnectionError, MAX_BODY_BYTES
from mimblewimble.p2p.message import MAINNET_MAGIC, MessageType, pack_header


def _socket_pair_connection():
    left, right = socket.socketpair()
    conn = Connection.from_socket(left, peer_addr="local-test", magic=MAINNET_MAGIC)
    return conn, right


def test_connect_opens_tcp_socket_and_receives_frame():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()

    accepted = threading.Event()

    def _server():
        try:
            server_conn, _ = listener.accept()
            accepted.set()
            server_conn.sendall(pack_header(MessageType.Ping, b""))
            server_conn.close()
        finally:
            listener.close()

    thread = threading.Thread(target=_server, daemon=True)
    thread.start()

    conn = Connection.connect(f"{host}:{port}", timeout=2.0, magic=MAINNET_MAGIC)
    try:
        msg_type, body = conn.recv_message()
        assert accepted.wait(1.0)
        assert msg_type == MessageType.Ping
        assert body == b""
    finally:
        conn.close()
        thread.join(timeout=1.0)


def test_connect_propagates_socket_open_error(monkeypatch):
    def _raise_connect_error(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", _raise_connect_error)

    with pytest.raises(OSError, match="connection refused"):
        Connection.connect("127.0.0.1:65535", timeout=0.1, magic=MAINNET_MAGIC)


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
