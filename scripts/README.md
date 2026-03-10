# Scripts

This directory contains standalone helper implementations that are optional to use with the core library.

## MySQL node storage adapter

- File: [mysql_node_storage.py](mysql_node_storage.py)
- Class: `MySQLNodeStorage`
- Purpose: Persist `PeerStore` node metadata and chain payloads using MySQL by implementing the `NodeStorage` adapter interface.

### Requirements

Install the MySQL connector package:

```bash
pip install mysql-connector-python
```

### What is stored

`MySQLNodeStorage` persists the `NodeRecord` fields:

- `addr` (primary key)
- `last_seen`
- `supports_pibd`
- `supports_txhashset`
- `total_difficulty`

It also persists additional `NodeStorage` payloads:

- headers (`store_headers`, `get_headers`)
- blocks (`store_blocks`, `get_blocks`)
- outputs (`store_outputs`, `get_outputs`)

When `auto_create_table=True`, the adapter creates these tables automatically if they do not exist:

- `known_nodes` (or your configured `table_name`)
- `<table_name>_headers`
- `<table_name>_blocks`
- `<table_name>_outputs`

### Implementation summary

`MySQLNodeStorage` supports:

- node upsert/remove for peer lifecycle persistence
- batched upsert for headers/blocks/outputs
- ordered reads with optional `limit`
- explicit `commit()` support for non-autocommit mode
- context-manager cleanup via `with ... as storage:`

The in-memory equivalent (`NodeStorageInMemory`) implements the same API, which keeps test and production behavior aligned.

### Usage

```python
from mimblewimble.p2p.peers import PeerStore
from scripts.mysql_node_storage import MySQLNodeStorage

storage = MySQLNodeStorage(
    host="127.0.0.1",
    port=3306,
    user="root",
    password="secret",
    database="mimblewimble",
    table_name="known_nodes",
    auto_create_table=True,
)

peer_store = PeerStore(node_storage=storage)
```

### Preferred peer construction snippet

Use `PeerStore.connect_outbound(...)` so peers are created with automatic storage wiring:

```python
from mimblewimble.p2p.peers import PeerStore
from scripts.mysql_node_storage import MySQLNodeStorage

storage = MySQLNodeStorage(
    host="127.0.0.1",
    user="root",
    password="secret",
    database="mimblewimble",
)
peer_store = PeerStore(node_storage=storage)

peer = peer_store.connect_outbound(
    addr="1.2.3.4:13414",
    my_addr="0.0.0.0:13414",
    genesis_hash=bytes.fromhex("00" * 32),
    total_difficulty=0,
    start=True,
    add=True,
    adapter=my_chain_adapter,
)
```

### Chain payload snippets

Store and query headers:

```python
from mimblewimble.p2p.peers import HeaderRecord

peer_store.store_headers([
    HeaderRecord(hash_hex="abc123", height=100, parent_hash_hex="def456", total_difficulty=9999, raw=b"..."),
])

latest_headers = peer_store.get_headers(limit=10)
```

Store and query blocks:

```python
from mimblewimble.p2p.peers import BlockRecord

peer_store.store_blocks([
    BlockRecord(hash_hex="blockhash", height=100, header_hash_hex="abc123", raw=b"..."),
])

latest_blocks = peer_store.get_blocks(limit=10)
```

Store and query outputs:

```python
from mimblewimble.p2p.peers import OutputRecord

peer_store.store_outputs([
    OutputRecord(commitment_hex="commitment", block_hash_hex="blockhash", height=100, status="snapshot", raw=b"..."),
])

latest_outputs = peer_store.get_outputs(limit=10)
```

### Notes

- By default, the adapter uses `autocommit=False` and commits after write operations.
- You can pass `autocommit=True` if your deployment prefers immediate commit behavior.
- The adapter also supports context-manager usage:

```python
from scripts.mysql_node_storage import MySQLNodeStorage

with MySQLNodeStorage(
    host="127.0.0.1",
    user="root",
    password="secret",
    database="mimblewimble",
) as storage:
    ...
```

## Live sync smoke script

- File: [sync_headers_live.py](sync_headers_live.py)
- Purpose: Run a manual live header-sync smoke check against a real Grin node.
- Note: This script is intentionally in `scripts/` (not `tests/`) so automated test suites remain self-contained.

### Environment variables

- `GRIN_NODE_URL` (required), e.g. `http://127.0.0.1:3413`
- `GRIN_P2P_ADDR` (optional), default `127.0.0.1:3414`

### Run snippet

PowerShell:

```powershell
$env:GRIN_NODE_URL="http://127.0.0.1:3413"
$env:GRIN_P2P_ADDR="127.0.0.1:3414"
python scripts/sync_headers_live.py
```

Bash:

```bash
GRIN_NODE_URL=http://127.0.0.1:3413 GRIN_P2P_ADDR=127.0.0.1:3414 python scripts/sync_headers_live.py
```

### What it checks

- chain tip fetch via JSON-RPC (`/v2/chain`)
- genesis header fetch
- outbound P2P `Hand/Shake`
- `GetHeaders` request and non-empty `Headers` response
