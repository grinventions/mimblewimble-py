"""
mimblewimble/p2p/connection.py

Low-level TCP connection wrapper for the Grin P2P protocol.

Handles:
  - Connecting to / accepting from a peer
  - Sending and receiving length-framed Grin messages
  - Non-blocking reads with a read-buffer
"""

from __future__ import annotations

import errno
import logging
import socket
import struct
from typing import Optional, Tuple

from mimblewimble.p2p.message import (
    HEADER_LEN,
    MAINNET_MAGIC,
    MessageType,
    unpack_header,
)

log = logging.getLogger(__name__)

# Maximum allowed body size (32 MiB) — prevent memory exhaustion
MAX_BODY_BYTES: int = 32 * 1024 * 1024

# Default connect / IO timeout in seconds
DEFAULT_TIMEOUT: float = 30.0


class ConnectionError(Exception):
    """Raised when the connection is closed or a protocol error occurs."""


class Connection:
    """Wraps a TCP socket and exposes Grin message framing.

    Usage::

        conn = Connection.connect("127.0.0.1:13414", timeout=10.0)
        conn.send_raw(framed_bytes)
        msg_type, body = conn.recv_message()
        conn.close()
    """

    def __init__(
        self,
        sock: socket.socket,
        peer_addr: str = "",
        magic: bytes = MAINNET_MAGIC,
    ) -> None:
        self._sock = sock
        self._sock.settimeout(DEFAULT_TIMEOUT)
        self.peer_addr = peer_addr
        self._magic = magic
        self._buf = bytearray()
        self.closed = False

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def connect(
        cls,
        addr: str,
        timeout: float = DEFAULT_TIMEOUT,
        magic: bytes = MAINNET_MAGIC,
    ) -> "Connection":
        """Open a TCP connection to *addr* (``"host:port"`` string).

        Raises:
            OSError if the connection fails.
        """
        host, port_str = addr.rsplit(":", 1)
        port = int(port_str)
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return cls(sock=sock, peer_addr=addr, magic=magic)

    @classmethod
    def from_socket(
        cls,
        sock: socket.socket,
        peer_addr: str = "",
        magic: bytes = MAINNET_MAGIC,
    ) -> "Connection":
        """Wrap an already-connected socket (for inbound connections)."""
        return cls(sock=sock, peer_addr=peer_addr, magic=magic)

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send_raw(self, data: bytes) -> None:
        """Send *data* in its entirety over the socket."""
        if self.closed:
            raise ConnectionError("Connection is closed")
        try:
            self._sock.sendall(data)
        except OSError as e:
            self.closed = True
            raise ConnectionError(f"Send failed: {e}") from e

    # ------------------------------------------------------------------
    # Receive
    # ------------------------------------------------------------------

    def recv_message(self) -> Tuple[MessageType, bytes]:
        """Block until a complete message is available and return (type, body).

        Raises:
            ConnectionError on EOF or protocol error.
        """
        # Ensure we have the header
        header_raw = self._recv_exactly(HEADER_LEN)
        magic, msg_type, body_len = unpack_header(header_raw)

        if magic != self._magic:
            raise ConnectionError(
                f"Magic mismatch: expected {self._magic.hex()}, got {magic.hex()}"
            )
        if body_len > MAX_BODY_BYTES:
            raise ConnectionError(f"Body too large: {body_len} > {MAX_BODY_BYTES}")

        body = self._recv_exactly(body_len) if body_len > 0 else b""
        log.debug(
            "Recv %s body=%d bytes from %s", msg_type.name, body_len, self.peer_addr
        )
        return msg_type, bytes(body)

    def recv_message_nonblocking(self) -> Optional[Tuple[MessageType, bytes]]:
        """Return a message if one is buffered; otherwise return None.

        Uses non-blocking socket reads to drain into ``self._buf``.
        """
        self._sock.setblocking(False)
        try:
            while True:
                chunk = self._sock.recv(65536)
                if not chunk:
                    self.closed = True
                    raise ConnectionError("Peer closed connection")
                self._buf.extend(chunk)
        except BlockingIOError:
            pass
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                self.closed = True
                raise ConnectionError(f"Recv error: {e}") from e
        finally:
            self._sock.setblocking(True)

        if len(self._buf) < HEADER_LEN:
            return None

        try:
            magic, msg_type, body_len = unpack_header(bytes(self._buf[:HEADER_LEN]))
        except ValueError as e:
            self.closed = True
            raise ConnectionError(f"Invalid message header: {e}") from e

        if magic != self._magic:
            self.closed = True
            raise ConnectionError(
                f"Magic mismatch: expected {self._magic.hex()}, got {magic.hex()}"
            )
        if body_len > MAX_BODY_BYTES:
            self.closed = True
            raise ConnectionError(f"Body too large: {body_len} > {MAX_BODY_BYTES}")

        total = HEADER_LEN + body_len
        if len(self._buf) < total:
            return None
        del self._buf[:HEADER_LEN]
        body = bytes(self._buf[:body_len])
        del self._buf[:body_len]
        return msg_type, body

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying socket."""
        if not self.closed:
            self.closed = True
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _recv_exactly(self, n: int) -> bytearray:
        """Read exactly *n* bytes from the socket, draining the buffer first."""
        result = bytearray()
        # Drain pre-buffered bytes first
        if self._buf:
            take = min(n, len(self._buf))
            result.extend(self._buf[:take])
            del self._buf[:take]
        while len(result) < n:
            try:
                chunk = self._sock.recv(n - len(result))
            except OSError as e:
                self.closed = True
                raise ConnectionError(f"Recv failed: {e}") from e
            if not chunk:
                self.closed = True
                raise ConnectionError("Peer closed connection unexpectedly")
            result.extend(chunk)
        return result

    def __repr__(self) -> str:
        return f"Connection(peer={self.peer_addr!r}, closed={self.closed})"
