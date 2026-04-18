"""Live-network PIBD sync probes.

These tests are opt-in and require a reachable Grin P2P node.
Set RUN_LIVE_P2P=1 to enable.
"""

from __future__ import annotations

import os

import pytest

from scripts.sync_headers_live import run_live_header_sync_smoke


pytestmark = pytest.mark.live_network


@pytest.mark.skipif(
    os.getenv("RUN_LIVE_P2P", "0") != "1",
    reason="Set RUN_LIVE_P2P=1 to run live network tests",
)
def test_live_handshake_header_and_state_sync_probe():
    report = run_live_header_sync_smoke(require_state_sync=True)

    assert report.headers_count > 0
    assert report.version >= 1
    assert report.txhashset_hash_hex is not None
    assert report.txhashset_height is not None
    assert report.txhashset_bytes_len is not None
