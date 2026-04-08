"""Live Grin sync smoke checks (not auto-collected by pytest).

This script intentionally lives under `scripts/` and avoids a `test_*.py` name
so CI/unit test runs remain self-contained and deterministic.

Usage (PowerShell):
    $env:GRIN_NODE_URL="http://127.0.0.1:3413"
    $env:GRIN_P2P_ADDR="127.0.0.1:3414"
    python scripts/sync_headers_live.py
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from ipaddress import ip_address

from mimblewimble.p2p.message import MAINNET_MAGIC

DEFAULT_GRIN_P2P_ADDR = "127.0.0.1:3414"
DEFAULT_MY_ADDR = "0.0.0.0:13414"

# Grin wire message type identifiers.
MSG_HAND = 1
MSG_SHAKE = 2
MSG_PING = 3
MSG_PONG = 4
MSG_GET_HEADERS = 7
MSG_HEADER = 8
MSG_HEADERS = 9
MSG_TXHASHSET_REQUEST = 16
MSG_TXHASHSET_ARCHIVE = 17
MSG_BAN_REASON = 18

# Capability bits mirrored from Grin p2p/src/types.rs.
CAP_HEADER_HIST = 1 << 0
CAP_TXHASHSET_HIST = 1 << 1
CAP_PEER_LIST = 1 << 2
CAP_TX_KERNEL_HASH = 1 << 3
CAP_PIBD_HIST = 1 << 4
CAP_PIBD_HIST_1 = 1 << 6
CAP_FULL_NODE = (
    CAP_HEADER_HIST
    | CAP_TXHASHSET_HIST
    | CAP_PEER_LIST
    | CAP_TX_KERNEL_HASH
    | CAP_PIBD_HIST
    | CAP_PIBD_HIST_1
)

# Canonical mainnet genesis hash from upstream grin/core/src/genesis.rs.
MAINNET_GENESIS_HASH = bytes.fromhex(
    "40adad0aec27797b48840aa9e00472015c21baea118ce7a2ff1a82c0f8f5bf82"
)


class LiveSyncError(RuntimeError):
    pass


@dataclass
class LiveSyncReport:
    requested_target: str
    connected_target: str
    version: int
    total_difficulty: int
    supports_pibd: bool
    headers_count: int
    txhashset_hash_hex: str | None = None
    txhashset_height: int | None = None
    txhashset_bytes_len: int | None = None


def _parse_addr(addr: str) -> tuple[str, int]:
    host, port_str = addr.rsplit(":", 1)
    return host, int(port_str)


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_connect_targets(addr: str) -> list[str]:
    host, port = _parse_addr(addr)
    if _is_ip_literal(host):
        return [addr]

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LiveSyncError(f"Cannot resolve host {host!r}: {exc}") from exc

    targets: list[str] = []
    seen: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        # Prefer IPv4 ordering first; IPv6 can still be added afterwards.
        target = f"{ip}:{port}"
        if family == socket.AF_INET and target not in seen:
            targets.insert(0, target)
            seen.add(target)
        elif target not in seen:
            targets.append(target)
            seen.add(target)

    if not targets:
        raise LiveSyncError(f"Cannot resolve host {host!r}: empty result")
    return targets


def _resolve_sender_addr(remote_addr: str, configured_addr: str) -> str:
    host, port = _parse_addr(configured_addr)
    if host != "0.0.0.0":
        return configured_addr

    remote_host, remote_port = _parse_addr(remote_addr)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((remote_host, remote_port))
        local_ip = probe.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    finally:
        probe.close()

    return f"{local_ip}:{port}"


def _encode_peer_addr(addr: str) -> bytes:
    host, port = _parse_addr(addr)
    try:
        ip = ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise LiveSyncError(f"Cannot resolve host {host!r}: {exc}") from exc
        if not infos:
            raise LiveSyncError(f"Cannot resolve host {host!r}: empty result")
        # Prefer IPv4 if available to match common mainnet peer addresses.
        chosen = None
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                chosen = sockaddr[0]
                break
            if chosen is None:
                chosen = sockaddr[0]
        ip = ip_address(chosen)

    if ip.version == 4:
        return struct.pack(">B", 0) + ip.packed + struct.pack(">H", port)

    segments = ip.exploded.split(":")
    body = struct.pack(">B", 1)
    for segment in segments:
        body += struct.pack(">H", int(segment, 16))
    body += struct.pack(">H", port)
    return body


def _encode_len_prefixed_bytes(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _pack_grin_message(msg_type: int, body: bytes) -> bytes:
    return MAINNET_MAGIC + struct.pack(">BQ", msg_type, len(body)) + body


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        data = sock.recv(length - len(chunks))
        if not data:
            raise LiveSyncError("Peer closed connection unexpectedly")
        chunks.extend(data)
    return bytes(chunks)


def _recv_grin_message(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 11)
    if header[:2] != MAINNET_MAGIC:
        raise LiveSyncError(
            f"Magic mismatch: expected {MAINNET_MAGIC.hex()} got {header[:2].hex()}"
        )
    msg_type = header[2]
    body_len = struct.unpack_from(">Q", header, 3)[0]
    body = _recv_exact(sock, body_len) if body_len > 0 else b""
    return msg_type, body


def _build_hand(sender_addr: str, receiver_addr: str, genesis_hash: bytes) -> bytes:
    nonce = int.from_bytes(os.urandom(8), "big")
    user_agent = b"MW/mimblewimble-py/0.1.0"
    body = struct.pack(">IIQQ", 3, CAP_FULL_NODE, nonce, 0)
    body += _encode_peer_addr(sender_addr)
    body += _encode_peer_addr(receiver_addr)
    body += _encode_len_prefixed_bytes(user_agent)
    body += genesis_hash[:32].ljust(32, b"\x00")
    return _pack_grin_message(MSG_HAND, body)


def _parse_shake(body: bytes) -> tuple[int, int, int, str, bytes]:
    if len(body) < 4 + 4 + 8 + 8 + 32:
        raise LiveSyncError(f"Shake message too short: {len(body)} bytes")
    version, capabilities, total_difficulty = struct.unpack_from(">IIQ", body, 0)
    offset = 4 + 4 + 8
    user_agent_len = struct.unpack_from(">Q", body, offset)[0]
    offset += 8
    user_agent = body[offset : offset + user_agent_len].decode("utf-8", "replace")
    offset += user_agent_len
    genesis_hash = body[offset : offset + 32]
    return version, capabilities, total_difficulty, user_agent, genesis_hash


def _send_get_headers(sock: socket.socket, locator: list[bytes]) -> None:
    if len(locator) > 20:
        locator = locator[:20]
    body = struct.pack(">B", len(locator))
    for h in locator:
        body += h[:32].ljust(32, b"\x00")
    sock.sendall(_pack_grin_message(MSG_GET_HEADERS, body))


def _send_txhashset_request(sock: socket.socket, block_hash: bytes, height: int) -> None:
    body = block_hash[:32].ljust(32, b"\x00") + struct.pack(">Q", height)
    sock.sendall(_pack_grin_message(MSG_TXHASHSET_REQUEST, body))


def get_mainnet_genesis_hash() -> bytes:
    return MAINNET_GENESIS_HASH


def run_live_header_sync_smoke(
    p2p_addr: str | None = None,
    my_addr: str | None = None,
    require_state_sync: bool = False,
) -> LiveSyncReport:
    requested_target = p2p_addr or os.getenv("GRIN_P2P_ADDR", DEFAULT_GRIN_P2P_ADDR)
    local_addr = my_addr or os.getenv("GRIN_MY_ADDR", DEFAULT_MY_ADDR)

    genesis_hash = get_mainnet_genesis_hash()
    sender_addr = _resolve_sender_addr(requested_target, local_addr)

    connect_targets = _resolve_connect_targets(requested_target)
    sock = None
    selected_target = None
    last_error: Exception | None = None
    for target in connect_targets:
        remote_host, remote_port = _parse_addr(target)
        try:
            s = socket.create_connection((remote_host, remote_port), timeout=10.0)
            s.settimeout(30.0)
            sock = s
            selected_target = target
            break
        except OSError as exc:
            last_error = exc
            continue

    if sock is None or selected_target is None:
        raise LiveSyncError(
            f"Unable to connect to any target for {requested_target}: {last_error}"
        )

    try:
        sock.sendall(_build_hand(sender_addr, selected_target, genesis_hash))
        msg_type, body = _recv_grin_message(sock)
        if msg_type != MSG_SHAKE:
            raise LiveSyncError(f"Expected Shake ({MSG_SHAKE}), got {msg_type}")

        version, capabilities, total_difficulty, user_agent, peer_genesis = _parse_shake(
            body
        )
        if peer_genesis != genesis_hash:
            raise LiveSyncError(
                f"Genesis mismatch: peer={peer_genesis.hex()} local={genesis_hash.hex()}"
            )

        supports_pibd = bool(capabilities & CAP_PIBD_HIST)
        print(
            "Handshake accepted with "
            f"{selected_target}; version={version}; difficulty={total_difficulty}; "
            f"pibd={supports_pibd}; agent={user_agent}"
        )

        _send_get_headers(sock, [genesis_hash])

        deadline = time.monotonic() + 30.0
        headers_count = 0
        while time.monotonic() < deadline:
            msg_type, body = _recv_grin_message(sock)
            if msg_type == MSG_PING and len(body) >= 16:
                # Echo liveness data back as Pong to remain in good standing.
                sock.sendall(_pack_grin_message(MSG_PONG, body[:16]))
                continue

            if msg_type == MSG_HEADERS:
                if len(body) < 2:
                    raise LiveSyncError("Received malformed Headers response")
                n_headers = struct.unpack_from(">H", body, 0)[0]
                if n_headers == 0:
                    raise LiveSyncError("Received empty headers response")
                headers_count = n_headers
                print(f"Received {n_headers} headers (sync started)")
                break

            if msg_type == MSG_HEADER:
                print("Received Header message (sync started)")
                headers_count = 1
                break

            if msg_type == MSG_BAN_REASON:
                raise LiveSyncError("Peer responded with BanReason")

        if headers_count == 0:
            raise LiveSyncError("Timed out waiting for Headers response")

        report = LiveSyncReport(
            requested_target=requested_target,
            connected_target=selected_target,
            version=version,
            total_difficulty=total_difficulty,
            supports_pibd=supports_pibd,
            headers_count=headers_count,
        )

        # Stage-2 probe: request TxHashSet metadata at genesis. This validates
        # state-sync message path beyond header sync without downloading archive bytes.
        _send_txhashset_request(sock, genesis_hash, 0)
        print("Requested TxHashSet archive metadata (state sync probe)")

        state_deadline = time.monotonic() + 30.0
        while time.monotonic() < state_deadline:
            msg_type, body = _recv_grin_message(sock)
            if msg_type == MSG_PING and len(body) >= 16:
                sock.sendall(_pack_grin_message(MSG_PONG, body[:16]))
                continue

            if msg_type == MSG_TXHASHSET_ARCHIVE:
                if len(body) < 48:
                    raise LiveSyncError("Received malformed TxHashSetArchive message")
                block_hash = body[:32]
                height = struct.unpack_from(">Q", body, 32)[0]
                bytes_len = struct.unpack_from(">Q", body, 40)[0]
                report.txhashset_hash_hex = block_hash.hex()
                report.txhashset_height = height
                report.txhashset_bytes_len = bytes_len
                print(
                    "Received TxHashSetArchive metadata "
                    f"(hash={block_hash.hex()[:12]}.. height={height} bytes={bytes_len})"
                )
                return report

            if msg_type == MSG_BAN_REASON:
                raise LiveSyncError("Peer responded with BanReason during state sync probe")

        if require_state_sync:
            raise LiveSyncError("Timed out waiting for TxHashSetArchive response")
        return report
    finally:
        sock.close()


if __name__ == "__main__":
    require_state = os.getenv("GRIN_REQUIRE_STATE_SYNC", "1") != "0"
    run_live_header_sync_smoke(require_state_sync=require_state)
    print("Live sync smoke check passed")
