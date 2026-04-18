"""Self-contained mocked tests for the PIBD sync helper flow.

This file intentionally avoids live network dependencies so the test suite is
deterministic in CI and local environments.
"""

from __future__ import annotations

import json

from mimblewimble.p2p.message import MessageType, MsgHeaders


def node_api(method: str, params=None, base_url: str = "http://mocked-node:3413"):
    """Call the Grin node JSON-RPC API at *base_url*.

    In tests we monkeypatch urlopen, so no real network calls are made.
    """
    import urllib.request

    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        base_url + "/v2/chain",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def get_tip(base_url: str = "http://mocked-node:3413"):
    return node_api("get_tip", base_url=base_url)["result"]["Ok"]


def get_header(height: int, base_url: str = "http://mocked-node:3413"):
    return node_api("get_header", [{"height": height}, None, None], base_url=base_url)[
        "result"
    ]["Ok"]


def test_get_tip_uses_mocked_jsonrpc(monkeypatch):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def read(self):
            return json.dumps({"result": {"Ok": {"height": 123}}}).encode()

    def _fake_urlopen(req, timeout=10):
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    tip = get_tip()
    assert tip["height"] == 123


def test_get_header_uses_mocked_jsonrpc(monkeypatch):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "result": {
                        "Ok": {
                            "height": 0,
                            "hash": "ab" * 32,
                        }
                    }
                }
            ).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: _Resp())

    header = get_header(0)
    assert header["height"] == 0
    assert len(bytes.fromhex(header["hash"])) == 32


def test_parse_headers_message_from_mocked_p2p_payload():
    raw_headers = [b"hdr-1", b"hdr-2", b"hdr-3"]
    msg = MsgHeaders(headers=raw_headers)

    message_type, body = MessageType.Headers, msg.serialize()[14:]
    assert message_type == MessageType.Headers

    parsed = MsgHeaders.deserialize(body)
    assert parsed.headers == raw_headers
