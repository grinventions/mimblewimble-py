"""
MySQL-backed NodeStorage adapter for mimblewimble-py.

This module provides `MySQLNodeStorage`, an implementation of the
`mimblewimble.p2p.peers.NodeStorage` interface that persists peer node metadata
in a MySQL table.

Requirements:
    pip install mysql-connector-python

Example:
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
    store = PeerStore(node_storage=storage)
"""

from __future__ import annotations

import threading
from typing import List

from mimblewimble.p2p.peers import (
    BlockRecord,
    HeaderRecord,
    NodeRecord,
    NodeStorage,
    OutputRecord,
)


class MySQLNodeStorage(NodeStorage):
    """MySQL persistence adapter for PeerStore node metadata."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        database: str,
        port: int = 3306,
        table_name: str = "known_nodes",
        auto_create_table: bool = True,
        autocommit: bool = False,
        connect_timeout: int = 10,
    ) -> None:
        self._table_name = table_name
        self._headers_table = f"{table_name}_headers"
        self._blocks_table = f"{table_name}_blocks"
        self._outputs_table = f"{table_name}_outputs"
        self._autocommit = autocommit
        self._lock = threading.Lock()

        try:
            import mysql.connector  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "MySQLNodeStorage requires 'mysql-connector-python'. "
                "Install it with: pip install mysql-connector-python"
            ) from e

        self._mysql_connector = mysql.connector
        self._conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            autocommit=autocommit,
            connection_timeout=connect_timeout,
        )

        if auto_create_table:
            self._ensure_table()

    def _ensure_table(self) -> None:
        query_nodes = f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                addr VARCHAR(255) PRIMARY KEY,
                last_seen DOUBLE NOT NULL,
                supports_pibd BOOLEAN NOT NULL,
                supports_txhashset BOOLEAN NOT NULL,
                total_difficulty BIGINT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        query_headers = f"""
            CREATE TABLE IF NOT EXISTS {self._headers_table} (
                hash_hex VARCHAR(64) PRIMARY KEY,
                height BIGINT NOT NULL,
                parent_hash_hex VARCHAR(64) NOT NULL,
                total_difficulty BIGINT NOT NULL,
                raw_blob LONGBLOB NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_headers_height (height)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        query_blocks = f"""
            CREATE TABLE IF NOT EXISTS {self._blocks_table} (
                hash_hex VARCHAR(64) PRIMARY KEY,
                height BIGINT NOT NULL,
                header_hash_hex VARCHAR(64) NOT NULL,
                raw_blob LONGBLOB NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_blocks_height (height)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        query_outputs = f"""
            CREATE TABLE IF NOT EXISTS {self._outputs_table} (
                commitment_hex VARCHAR(128) PRIMARY KEY,
                block_hash_hex VARCHAR(64) NOT NULL,
                height BIGINT NOT NULL,
                status VARCHAR(32) NOT NULL,
                raw_blob LONGBLOB NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_outputs_height (height)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._conn.cursor() as cur:
            cur.execute(query_nodes)
            cur.execute(query_headers)
            cur.execute(query_blocks)
            cur.execute(query_outputs)
        if not self._autocommit:
            self._conn.commit()

    def get_all_nodes(self) -> List[NodeRecord]:
        query = f"""
            SELECT addr, last_seen, supports_pibd, supports_txhashset, total_difficulty
            FROM {self._table_name}
            ORDER BY last_seen DESC
        """
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

        records: List[NodeRecord] = []
        for row in rows:
            records.append(
                NodeRecord(
                    addr=str(row[0]),
                    last_seen=float(row[1]),
                    supports_pibd=bool(row[2]),
                    supports_txhashset=bool(row[3]),
                    total_difficulty=int(row[4]),
                )
            )
        return records

    def upsert_node(self, node: NodeRecord) -> None:
        query = f"""
            INSERT INTO {self._table_name}
                (addr, last_seen, supports_pibd, supports_txhashset, total_difficulty)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                last_seen = VALUES(last_seen),
                supports_pibd = VALUES(supports_pibd),
                supports_txhashset = VALUES(supports_txhashset),
                total_difficulty = VALUES(total_difficulty)
        """
        values = (
            node.addr,
            node.last_seen,
            node.supports_pibd,
            node.supports_txhashset,
            node.total_difficulty,
        )
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query, values)
            if not self._autocommit:
                self._conn.commit()

    def remove_node(self, addr: str) -> None:
        query = f"DELETE FROM {self._table_name} WHERE addr = %s"
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query, (addr,))
            if not self._autocommit:
                self._conn.commit()

    def store_headers(self, headers: List[HeaderRecord]) -> None:
        if not headers:
            return
        query = f"""
            INSERT INTO {self._headers_table}
                (hash_hex, height, parent_hash_hex, total_difficulty, raw_blob)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                height = VALUES(height),
                parent_hash_hex = VALUES(parent_hash_hex),
                total_difficulty = VALUES(total_difficulty),
                raw_blob = VALUES(raw_blob)
        """
        values = [
            (
                h.hash_hex,
                h.height,
                h.parent_hash_hex,
                h.total_difficulty,
                h.raw if h.raw else None,
            )
            for h in headers
        ]
        with self._lock:
            with self._conn.cursor() as cur:
                cur.executemany(query, values)
            if not self._autocommit:
                self._conn.commit()

    def get_headers(self, limit: int | None = None) -> List[HeaderRecord]:
        query = f"""
            SELECT hash_hex, height, parent_hash_hex, total_difficulty, raw_blob
            FROM {self._headers_table}
            ORDER BY height DESC
        """
        params = None
        if limit is not None:
            query += " LIMIT %s"
            params = (limit,)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [
            HeaderRecord(
                hash_hex=str(r[0]),
                height=int(r[1]),
                parent_hash_hex=str(r[2]),
                total_difficulty=int(r[3]),
                raw=bytes(r[4]) if r[4] is not None else b"",
            )
            for r in rows
        ]

    def store_blocks(self, blocks: List[BlockRecord]) -> None:
        if not blocks:
            return
        query = f"""
            INSERT INTO {self._blocks_table}
                (hash_hex, height, header_hash_hex, raw_blob)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                height = VALUES(height),
                header_hash_hex = VALUES(header_hash_hex),
                raw_blob = VALUES(raw_blob)
        """
        values = [
            (
                b.hash_hex,
                b.height,
                b.header_hash_hex,
                b.raw if b.raw else None,
            )
            for b in blocks
        ]
        with self._lock:
            with self._conn.cursor() as cur:
                cur.executemany(query, values)
            if not self._autocommit:
                self._conn.commit()

    def get_blocks(self, limit: int | None = None) -> List[BlockRecord]:
        query = f"""
            SELECT hash_hex, height, header_hash_hex, raw_blob
            FROM {self._blocks_table}
            ORDER BY height DESC
        """
        params = None
        if limit is not None:
            query += " LIMIT %s"
            params = (limit,)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [
            BlockRecord(
                hash_hex=str(r[0]),
                height=int(r[1]),
                header_hash_hex=str(r[2]),
                raw=bytes(r[3]) if r[3] is not None else b"",
            )
            for r in rows
        ]

    def store_outputs(self, outputs: List[OutputRecord]) -> None:
        if not outputs:
            return
        query = f"""
            INSERT INTO {self._outputs_table}
                (commitment_hex, block_hash_hex, height, status, raw_blob)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                block_hash_hex = VALUES(block_hash_hex),
                height = VALUES(height),
                status = VALUES(status),
                raw_blob = VALUES(raw_blob)
        """
        values = [
            (
                o.commitment_hex,
                o.block_hash_hex,
                o.height,
                o.status,
                o.raw if o.raw else None,
            )
            for o in outputs
        ]
        with self._lock:
            with self._conn.cursor() as cur:
                cur.executemany(query, values)
            if not self._autocommit:
                self._conn.commit()

    def get_outputs(self, limit: int | None = None) -> List[OutputRecord]:
        query = f"""
            SELECT commitment_hex, block_hash_hex, height, status, raw_blob
            FROM {self._outputs_table}
            ORDER BY height DESC
        """
        params = None
        if limit is not None:
            query += " LIMIT %s"
            params = (limit,)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [
            OutputRecord(
                commitment_hex=str(r[0]),
                block_hash_hex=str(r[1]),
                height=int(r[2]),
                status=str(r[3]),
                raw=bytes(r[4]) if r[4] is not None else b"",
            )
            for r in rows
        ]

    def commit(self) -> None:
        if not self._autocommit:
            with self._lock:
                self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "MySQLNodeStorage":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
