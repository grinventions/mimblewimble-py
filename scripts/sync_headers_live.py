"""Live Grin sync smoke checks (not auto-collected by pytest).

This script intentionally lives under `scripts/` and avoids a `test_*.py` name
so CI/unit test runs remain self-contained and deterministic.

Usage (PowerShell):
    $env:GRIN_NODE_URL="http://127.0.0.1:3413"
    $env:GRIN_P2P_ADDR="127.0.0.1:3414"
    python scripts/sync_headers_live.py
"""

from __future__ import annotations

import json
import os
import time
import urllib.request

from mimblewimble.p2p.connection import Connection
from mimblewimble.p2p.handshake import do_handshake_outbound
from mimblewimble.p2p.message import MessageType, MsgGetHeaders, MsgHeaders

GRIN_NODE_URL = os.getenv("GRIN_NODE_URL", "")
GRIN_P2P_ADDR = os.getenv("GRIN_P2P_ADDR", "127.0.0.1:3414")


class LiveSyncError(RuntimeError):
    pass


def node_api(method: str, params=None):
    if not GRIN_NODE_URL:
        raise LiveSyncError("GRIN_NODE_URL is required")

    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        GRIN_NODE_URL + "/v2/chain",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def get_tip():
    return node_api("get_tip")["result"]["Ok"]


def get_header(height: int):
    return node_api("get_header", [{"height": height}, None, None])["result"]["Ok"]


def run_live_header_sync_smoke() -> None:
    tip = get_tip()
    if "height" not in tip:
        raise LiveSyncError("Tip response missing height")

    genesis = get_header(0)
    genesis_hash = bytes.fromhex(genesis["hash"])

    conn = Connection.connect(GRIN_P2P_ADDR, timeout=15.0)
    try:
        hs = do_handshake_outbound(
            conn=conn,
            my_addr="0.0.0.0:13414",
            genesis_hash=genesis_hash,
        )
        print(
            f"Connected to {GRIN_P2P_ADDR}; version={hs.version}; pibd={hs.supports_pibd()}"
        )

        req = MsgGetHeaders(locator=[genesis_hash])
        conn.send_raw(req.serialize())

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            msg_type, body = conn.recv_message()
            if msg_type == MessageType.Headers:
                parsed = MsgHeaders.deserialize(body)
                if not parsed.headers:
                    raise LiveSyncError("Received empty headers response")
                print(f"Received {len(parsed.headers)} headers")
                return

        raise LiveSyncError("Timed out waiting for Headers response")
    finally:
        conn.close()


if __name__ == "__main__":
    run_live_header_sync_smoke()
    print("Live sync smoke check passed")
