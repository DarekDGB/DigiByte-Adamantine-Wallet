"""
SQLite Storage — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Database-backed WalletStorage implementation
- Atomic batch via SQLite transactions
- Minimal dependencies (stdlib sqlite3)
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Optional, Union

from core.storage.interface import WalletBatch, WalletStorage


def _encode(value: Any) -> str:
    # JSON is portable across clients/languages
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _decode(blob: str) -> Any:
    return json.loads(blob)


class _SQLiteBatch(WalletBatch):
    def __init__(self, store: "SQLiteWalletStorage") -> None:
        self._store = store
        self._closed = False

    def put(self, key: str, value: Any) -> None:
        if self._closed:
            raise RuntimeError("batch is closed")
        self._store._put_tx(key, value)

    def delete(self, key: str) -> None:
        if self._closed:
            raise RuntimeError("batch is closed")
        self._store._delete_tx(key)

    def commit(self) -> None:
        if self._closed:
            return
        self._store._commit_tx()
        self._closed = True

    def rollback(self) -> None:
        if self._closed:
            return
        self._store._rollback_tx()
        self._closed = True


class SQLiteWalletStorage(WalletStorage):
    """
    SQLite-backed WalletStorage.

    Schema: kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)

    Notes:
    - Values are stored as JSON strings
    - begin_batch() starts a transaction and returns a WalletBatch
    - Non-batch operations are wrapped in their own transaction implicitly
    """

    def __init__(self, db_path: Union[str, Path]) -> None:
        self._path = str(db_path)
        self._lock = RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.commit()
        self._in_tx = False

    # ---- internal tx helpers ----

    def _begin_tx(self) -> None:
        if self._in_tx:
            return
        self._conn.execute("BEGIN")
        self._in_tx = True

    def _commit_tx(self) -> None:
        if not self._in_tx:
            return
        self._conn.commit()
        self._in_tx = False

    def _rollback_tx(self) -> None:
        if not self._in_tx:
            return
        self._conn.rollback()
        self._in_tx = False

    def _put_tx(self, key: str, value: Any) -> None:
        blob = _encode(value)
        self._conn.execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, blob),
        )

    def _delete_tx(self, key: str) -> None:
        self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))

    # ---- WalletStorage interface ----

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            cur = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,))
            row = cur.fetchone()
            if row is None:
                return None
            return _decode(row[0])

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._put_tx(key, value)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def delete(self, key: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._delete_tx(key)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def exists(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute("SELECT 1 FROM kv WHERE key = ? LIMIT 1", (key,))
            return cur.fetchone() is not None

    def keys(self, prefix: str = "") -> Iterable[str]:
        with self._lock:
            if not prefix:
                cur = self._conn.execute("SELECT key FROM kv")
                return [r[0] for r in cur.fetchall()]
            cur = self._conn.execute(
                "SELECT key FROM kv WHERE key LIKE ?",
                (f"{prefix}%",),
            )
            return [r[0] for r in cur.fetchall()]

    def begin_batch(self) -> WalletBatch:
        with self._lock:
            self._begin_tx()
            return _SQLiteBatch(self)

    def close(self) -> None:
        with self._lock:
            try:
                if self._in_tx:
                    self._conn.rollback()
            finally:
                self._conn.close()
                self._in_tx = False
