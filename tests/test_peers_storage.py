from types import SimpleNamespace

from mimblewimble.p2p.peers import (
    BlockRecord,
    HeaderRecord,
    NodeRecord,
    NodeStorage,
    NodeStorageInMemory,
    OutputRecord,
    PeerStore,
)
from mimblewimble.p2p.handshake import HandshakeResult


class _CustomNodeStorage(NodeStorage):
    def __init__(self):
        self.nodes = {}
        self.headers = {}
        self.blocks = {}
        self.outputs = {}
        self.commits = 0

    def get_all_nodes(self):
        return list(self.nodes.values())

    def upsert_node(self, node: NodeRecord) -> None:
        self.nodes[node.addr] = node

    def remove_node(self, addr: str) -> None:
        self.nodes.pop(addr, None)

    def store_headers(self, headers):
        for header in headers:
            self.headers[header.hash_hex] = header

    def get_headers(self, limit=None):
        values = list(self.headers.values())
        return values[:limit] if limit is not None else values

    def store_blocks(self, blocks):
        for block in blocks:
            self.blocks[block.hash_hex] = block

    def get_blocks(self, limit=None):
        values = list(self.blocks.values())
        return values[:limit] if limit is not None else values

    def store_outputs(self, outputs):
        for output in outputs:
            self.outputs[output.commitment_hex] = output

    def get_outputs(self, limit=None):
        values = list(self.outputs.values())
        return values[:limit] if limit is not None else values

    def commit(self) -> None:
        self.commits += 1


class _FakePeer:
    def __init__(
        self,
        addr="127.0.0.1:13414",
        alive=True,
        pibd=True,
        txhashset=True,
        difficulty=42,
        seen=123.0,
    ):
        self.addr = addr
        self._alive = alive
        self._pibd = pibd
        self._txhashset = txhashset
        self._seen = seen
        self.handshake = SimpleNamespace(genesis_block_difficulty=difficulty)

    def is_alive(self):
        return self._alive

    def supports_pibd(self):
        return self._pibd

    def supports_txhashset(self):
        return self._txhashset

    def last_seen(self):
        return self._seen


def test_peer_store_persists_added_peer_into_custom_storage():
    storage = _CustomNodeStorage()
    store = PeerStore(node_storage=storage)

    peer = _FakePeer(addr="10.0.0.1:13414", difficulty=777, seen=999.0)
    store.add(peer)

    assert "10.0.0.1:13414" in storage.nodes
    node = storage.nodes["10.0.0.1:13414"]
    assert node.total_difficulty == 777
    assert node.last_seen == 999.0
    assert node.supports_pibd is True
    assert node.supports_txhashset is True
    assert storage.commits == 1


def test_peer_store_remove_updates_custom_storage():
    storage = _CustomNodeStorage()
    store = PeerStore(node_storage=storage)

    peer = _FakePeer(addr="10.0.0.2:13414")
    store.add(peer)
    store.remove(peer.addr)

    assert peer.addr not in storage.nodes
    assert storage.commits == 2


def test_peer_store_known_nodes_reads_from_storage():
    storage = _CustomNodeStorage()
    store = PeerStore(node_storage=storage)

    peer_a = _FakePeer(addr="10.0.0.3:13414", difficulty=100)
    peer_b = _FakePeer(addr="10.0.0.4:13414", difficulty=200)
    store.add(peer_a)
    store.add(peer_b)

    known = {n.addr: n for n in store.known_nodes()}
    assert set(known.keys()) == {peer_a.addr, peer_b.addr}
    assert known[peer_b.addr].total_difficulty == 200


def test_peer_store_cull_dead_removes_from_storage():
    storage = _CustomNodeStorage()
    store = PeerStore(node_storage=storage)

    alive = _FakePeer(addr="10.0.0.5:13414", alive=True)
    dead = _FakePeer(addr="10.0.0.6:13414", alive=False)
    store.add(alive)
    store.add(dead)

    removed = store.cull_dead()

    assert removed == 1
    assert dead.addr not in storage.nodes
    assert alive.addr in storage.nodes


def test_node_storage_in_memory_store_and_get_chain_data():
    storage = NodeStorageInMemory()

    storage.store_headers(
        [
            HeaderRecord(hash_hex="h1", height=1, total_difficulty=10),
            HeaderRecord(hash_hex="h2", height=2, total_difficulty=20),
        ]
    )
    storage.store_blocks(
        [
            BlockRecord(hash_hex="b1", height=1, header_hash_hex="h1"),
            BlockRecord(hash_hex="b2", height=2, header_hash_hex="h2"),
        ]
    )
    storage.store_outputs(
        [
            OutputRecord(commitment_hex="c1", height=1, status="Unspent"),
            OutputRecord(commitment_hex="c2", height=2, status="Spent"),
        ]
    )

    headers = storage.get_headers()
    blocks = storage.get_blocks()
    outputs = storage.get_outputs()

    assert [h.hash_hex for h in headers] == ["h2", "h1"]
    assert [b.hash_hex for b in blocks] == ["b2", "b1"]
    assert [o.commitment_hex for o in outputs] == ["c2", "c1"]
    assert storage.get_headers(limit=1)[0].hash_hex == "h2"
    assert storage.get_blocks(limit=1)[0].hash_hex == "b2"
    assert storage.get_outputs(limit=1)[0].commitment_hex == "c2"


def test_peer_store_proxies_chain_storage_methods():
    storage = NodeStorageInMemory()
    store = PeerStore(node_storage=storage)

    store.store_headers([HeaderRecord(hash_hex="h10", height=10)])
    store.store_blocks([BlockRecord(hash_hex="b10", height=10)])
    store.store_outputs([OutputRecord(commitment_hex="c10", height=10)])

    assert store.get_headers(limit=1)[0].hash_hex == "h10"
    assert store.get_blocks(limit=1)[0].hash_hex == "b10"
    assert store.get_outputs(limit=1)[0].commitment_hex == "c10"


def test_peer_store_connect_outbound_wires_peer_store(monkeypatch):
    class _FakeConn:
        def __init__(self):
            self.peer_addr = "10.9.0.1:13414"
            self.closed = False

        def close(self):
            self.closed = True

    fake_conn = _FakeConn()

    def _fake_connect(addr, timeout=30.0, magic=None):
        return fake_conn

    def _fake_handshake(conn, my_addr, genesis_hash, total_difficulty=0):
        return HandshakeResult(
            version=1,
            capabilities=0,
            user_agent="test",
            genesis_hash=genesis_hash,
            peer_addr=conn.peer_addr,
            nonce=1,
        )

    monkeypatch.setattr("mimblewimble.p2p.connection.Connection.connect", _fake_connect)
    monkeypatch.setattr(
        "mimblewimble.p2p.handshake.do_handshake_outbound", _fake_handshake
    )

    storage = NodeStorageInMemory()
    store = PeerStore(node_storage=storage)

    peer = store.connect_outbound(
        addr="10.9.0.1:13414",
        my_addr="0.0.0.0:0",
        genesis_hash=b"\x11" * 32,
        start=False,
        add=True,
    )

    assert peer.addr == "10.9.0.1:13414"
    assert peer in store.all()
    assert store.known_nodes()[0].addr == "10.9.0.1:13414"
