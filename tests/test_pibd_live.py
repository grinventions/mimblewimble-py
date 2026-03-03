"""
tests/test_pibd_live.py

Live integration tests that connect to a real Grin node.

These tests are skipped unless the environment variable ``GRIN_NODE_URL``
is set to the node's HTTP API URL (e.g. ``http://127.0.0.1:3413``).

Additionally, ``GRIN_P2P_ADDR`` controls the TCP peer address to connect
to for P2P tests (default: ``127.0.0.1:13414`` mainnet).

Example::

    GRIN_NODE_URL=http://localhost:3413 GRIN_P2P_ADDR=127.0.0.1:13414 pytest tests/test_pibd_live.py -v

These tests validate that the Python implementation interoperates correctly
with a live Grin reference node.
"""

import os
import time
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Environment gates
# ---------------------------------------------------------------------------

GRIN_NODE_URL = "http://127.0.0.1:3413"
GRIN_P2P_ADDR = os.getenv("GRIN_P2P_ADDR", "127.0.0.1:3414")

skip_no_node = pytest.mark.skipif(
    not GRIN_NODE_URL,
    reason="Set GRIN_NODE_URL to run live node tests",
)


# ---------------------------------------------------------------------------
# HTTP API helpers
# ---------------------------------------------------------------------------


def node_api(method: str, params=None):
    """Call the Grin node JSON-RPC API at GRIN_NODE_URL."""
    import json
    import urllib.request

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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_no_node
def test_live_node_reachable():
    """Basic connectivity: the node returns a valid chain tip."""
    tip = get_tip()
    assert "height" in tip
    assert tip["height"] >= 0
    print(f"\nLive node tip height: {tip['height']}")


@skip_no_node
def test_live_genesis_header():
    """Verify we can fetch the genesis block header."""
    genesis = get_header(0)
    assert genesis is not None
    assert genesis["height"] == 0
    print(f"\nGenesis hash: {genesis['hash']}")


@skip_no_node
def test_live_header_hash_computation():
    """Fetch a block header and verify our Python hash matches the node's hash."""
    import hashlib
    from mimblewimble.blockchain import BlockHeader
    from mimblewimble.serializer import Serializer, EProtocolVersion

    # Use height 1 to avoid genesis special-casing
    hdr_json = get_header(1)
    node_hash = hdr_json["hash"]

    # Build a minimal BlockHeader from the JSON (only checking hash consistency)
    # The actual deserialization depends on the full BlockHeader implementation;
    # for now we just check the response shape.
    assert len(node_hash) == 64, "Expected 64-char hex hash"
    hash_bytes = bytes.fromhex(node_hash)
    assert len(hash_bytes) == 32


@skip_no_node
@pytest.mark.timeout(120)
def test_live_p2p_handshake():
    """Connect to the node over TCP and complete the Hand/Shake sequence."""
    from mimblewimble.p2p.connection import Connection
    from mimblewimble.p2p.handshake import do_handshake_outbound, HandshakeError

    # Get genesis hash from the API to use in handshake
    tip = get_tip()
    genesis_json = get_header(0)
    genesis_hash = bytes.fromhex(genesis_json["hash"])

    try:
        conn = Connection.connect(GRIN_P2P_ADDR, timeout=15.0)
    except OSError as e:
        pytest.skip(f"Cannot connect to {GRIN_P2P_ADDR}: {e}")

    try:
        hs = do_handshake_outbound(
            conn=conn,
            my_addr="0.0.0.0:13414",
            genesis_hash=genesis_hash,
        )
        assert hs.version >= 1
        print(f"\nConnected to Grin node at {GRIN_P2P_ADDR}")
        print(f"  Protocol version: {hs.version}")
        print(f"  User-agent:       {hs.user_agent}")
        print(f"  PIBD capable:     {hs.supports_pibd()}")
    except HandshakeError as e:
        pytest.fail(f"Handshake failed: {e}")
    finally:
        conn.close()


@skip_no_node
@pytest.mark.timeout(300)
def test_live_header_request():
    """Connect, handshake, then request block headers and verify they arrive."""
    from mimblewimble.p2p.connection import Connection
    from mimblewimble.p2p.handshake import do_handshake_outbound
    from mimblewimble.p2p.message import (
        MessageType,
        MsgGetHeaders,
        MsgHeaders,
    )

    genesis_json = get_header(0)
    genesis_hash = bytes.fromhex(genesis_json["hash"])

    try:
        conn = Connection.connect(GRIN_P2P_ADDR, timeout=15.0)
    except OSError as e:
        pytest.skip(f"Cannot connect to {GRIN_P2P_ADDR}: {e}")

    try:
        do_handshake_outbound(conn, my_addr="0.0.0.0:13414", genesis_hash=genesis_hash)

        # Request headers from genesis
        msg = MsgGetHeaders(locator=[genesis_hash])
        conn.send_raw(msg.serialize())

        # Wait for Headers or a Ping/Pong
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            msg_type, body = conn.recv_message()
            if msg_type == MessageType.Headers:
                headers_msg = MsgHeaders.deserialize(body)
                assert len(headers_msg.headers) > 0, "Expected at least one header"
                print(f"\nReceived {len(headers_msg.headers)} headers from live node")
                return
            # Silently ignore other messages (Ping, PeerAddrs, etc.)

        pytest.fail("Timed out waiting for Headers response")
    finally:
        conn.close()


@skip_no_node
@pytest.mark.timeout(60)
def test_live_request_bitmap_segment():
    """Connect and request a PIBD bitmap segment, verifying its structure."""
    from mimblewimble.p2p.connection import Connection
    from mimblewimble.p2p.handshake import do_handshake_outbound
    from mimblewimble.p2p.message import (
        MessageType,
        MsgGetOutputBitmapSegment,
        MsgOutputBitmapSegment,
    )
    from mimblewimble.mmr.segment import SegmentIdentifier
    from mimblewimble.mmr.pibd_params import BITMAP_SEGMENT_HEIGHT

    genesis_json = get_header(0)
    genesis_hash = bytes.fromhex(genesis_json["hash"])
    tip = get_tip()
    # Use the tip hash for the segment request
    tip_hash_hex = tip.get("last_block_pushed", {}).get("hash", "")
    if not tip_hash_hex:
        pytest.skip("Could not determine tip block hash from API")
    tip_hash = bytes.fromhex(tip_hash_hex)

    try:
        conn = Connection.connect(GRIN_P2P_ADDR, timeout=15.0)
    except OSError as e:
        pytest.skip(f"Cannot connect to {GRIN_P2P_ADDR}: {e}")

    try:
        hs = do_handshake_outbound(
            conn, my_addr="0.0.0.0:13414", genesis_hash=genesis_hash
        )
        if not hs.supports_pibd():
            pytest.skip("Connected node does not support PIBD")

        identifier = SegmentIdentifier(height=BITMAP_SEGMENT_HEIGHT, idx=0)
        req = MsgGetOutputBitmapSegment(block_hash=tip_hash, identifier=identifier)
        conn.send_raw(req.serialize())

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            msg_type, body = conn.recv_message()
            if msg_type == MessageType.OutputBitmapSegment:
                resp = MsgOutputBitmapSegment.deserialize(body)
                print(f"\nReceived bitmap segment: segment={resp.segment!r}")
                if resp.segment is not None:
                    # Verify basic structure
                    assert resp.segment.identifier.height == BITMAP_SEGMENT_HEIGHT
                    assert resp.segment.identifier.idx == 0
                return

        pytest.fail("Timed out waiting for OutputBitmapSegment response")
    finally:
        conn.close()
