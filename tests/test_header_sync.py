"""
tests/test_header_sync.py

Unit tests for the header-sync locator logic and the HeaderSync class.
"""

import pytest

from mimblewimble.p2p.header_sync import HeaderSync, build_locator, LOCATOR_SIZE

# ---------------------------------------------------------------------------
# Locator construction
# ---------------------------------------------------------------------------


class TestBuildLocator:
    def _hash_at(self, h: int):
        """Deterministic fake hash."""
        return h.to_bytes(32, "little")

    def test_empty_chain(self):
        locator = HeaderSync.build_locator(0, lambda h: None)
        assert locator == []

    def test_single_block(self):
        locator = HeaderSync.build_locator(1, self._hash_at)
        # Must include height 1 and genesis (height 0)
        assert self._hash_at(1) in locator
        assert self._hash_at(0) in locator

    def test_long_chain_max_length(self):
        locator = HeaderSync.build_locator(10000, self._hash_at)
        assert len(locator) <= LOCATOR_SIZE

    def test_genesis_always_included(self):
        locator = HeaderSync.build_locator(50, self._hash_at)
        assert self._hash_at(0) in locator

    def test_locator_is_descending_in_height(self):
        """Heights should decrease (most recent first)."""
        locator = HeaderSync.build_locator(20, self._hash_at)
        heights = [int.from_bytes(h, "little") for h in locator]
        assert heights == sorted(
            heights, reverse=True
        ), f"Locator not descending: {heights}"

    def test_exponential_step_back(self):
        """After the first 10 entries the step doubles."""
        locator = HeaderSync.build_locator(1000, self._hash_at)
        heights = [
            int.from_bytes(h, "little") for h in locator if h != self._hash_at(0)
        ]
        # Gaps between consecutive heights should grow
        if len(heights) > 11:
            gaps = [heights[i] - heights[i + 1] for i in range(10, len(heights) - 1)]
            assert max(gaps) > 10, "Expected growing step-back after first 10 items"

    def test_no_duplicates(self):
        locator = HeaderSync.build_locator(500, self._hash_at)
        assert len(set(locator)) == len(locator), "Duplicate hashes in locator"


# ---------------------------------------------------------------------------
# HeaderSync.check_run() integration
# ---------------------------------------------------------------------------


class MockPeerStore:
    """Minimal PeerStore mock for HeaderSync tests."""

    def __init__(self, peers=None):
        self._peers = peers or []

    def live(self):
        return _MockQuery(self._peers)

    def count(self):
        return len(self._peers)


class _MockQuery:
    def __init__(self, peers):
        self._peers = [p for p in peers if getattr(p, "_alive", True)]

    def live(self):
        return self

    def pibd(self):
        return _MockQuery([p for p in self._peers if getattr(p, "_pibd", True)])

    def txhashset(self):
        return _MockQuery([p for p in self._peers if getattr(p, "_txhashset", True)])

    def highest_difficulty(self):
        return self

    def pick(self):
        return self._peers[0] if self._peers else None

    def pick_n(self, n):
        return self._peers[:n]


class MockPeer:
    def __init__(self, addr="127.0.0.1:13414", difficulty=1000):
        self.addr = addr
        self._alive = True
        self._pibd = True
        self._txhashset = True
        self.handshake = _HS(difficulty)

    def is_alive(self):
        return self._alive

    def supports_pibd(self):
        return self._pibd

    def supports_txhashset(self):
        return self._txhashset

    def request_headers(self, locator):
        self._last_locator = locator


class _HS:
    def __init__(self, diff):
        self.genesis_block_difficulty = diff


class MockAdapter:
    def __init__(self):
        self._headers = []
        self._locator = [b"\x00" * 32]
        self._height = 0
        self._total_diff = 1000

    def get_locator(self):
        return self._locator

    def sync_block_headers(self, raw_headers):
        self._headers.extend(raw_headers)

    def best_height(self):
        return self._height

    def total_difficulty(self):
        return self._total_diff

    def genesis_hash(self):
        return b"\x00" * 32


class TestHeaderSync:
    def test_check_run_sends_request(self):
        peer = MockPeer()
        peers = MockPeerStore([peer])
        adapter = MockAdapter()
        hdr_sync = HeaderSync(adapter, peers)

        result = hdr_sync.check_run(1000, 2000)
        assert result is True
        assert hasattr(peer, "_last_locator")

    def test_check_run_no_peers(self):
        peers = MockPeerStore([])
        adapter = MockAdapter()
        hdr_sync = HeaderSync(adapter, peers)
        result = hdr_sync.check_run(1000, 2000)
        assert result is False

    def test_check_run_respects_interval(self):
        """check_run should not fire twice within HEADER_SYNC_INTERVAL."""
        import time

        peer = MockPeer()
        peers = MockPeerStore([peer])
        adapter = MockAdapter()
        hdr_sync = HeaderSync(adapter, peers)

        hdr_sync.check_run(1000, 2000)
        # Second call should be throttled
        peer._last_locator = None
        result = hdr_sync.check_run(1000, 2000)
        assert result is False
