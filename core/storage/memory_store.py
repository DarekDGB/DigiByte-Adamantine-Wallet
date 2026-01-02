"""
In-Memory Storage — Adamantine Wallet OS

Author: DarekDGB
License: MIT (see root LICENSE)

Purpose:
- Zero-dependency storage backend for tests + early development
- Supports atomic WalletBatch semantics
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, Iterable, Optional

from core.storage.interface import WalletBatch, WalletStorage


class _MemoryBatch(WalletBatch):
    def __init__(self, parent: "MemoryWalletStorage") -> None:
        self._parent = parent
        self._writes: Dict[str, Any] = {}
        self._deletes: set[str] = set()
        self._closed = False

    def put(self, key: str, value: Any) -> None:
        if self._closed:
            raise RuntimeError("batch is closed")
        self._writes[key] = value
        self._deletes.discard(key)

    def delete(self, key: str) -> None:
        if self._closed:
            raise RuntimeError("batch is closed")
        self._deletes.add(key)
        self._writes.pop(key, None)

    def commit(self) -> None:
        if self._closed:
            return
        with self._parent._lock:
            # apply deletes first
            for k in self._deletes:
                self._parent._data.pop(k, None)
            # then writes
            for k, v in self._writes.items():
                self._parent._data[k] = v
        self._closed = True

    def rollback(self) -> None:
        if self._closed:
            return
        self._writes.clear()
        self._deletes.clear()
        self._closed = True


class MemoryWalletStorage(WalletStorage):
    """
    Simple thread-safe in-memory storage.

    Notes:
    - Values are stored as-is (no serialization here)
    - Higher layers may serialize to dict/bytes if they want portability
    """

    def __init__(self, initial: Optional[Dict[str, Any]] = None) -> None:
        self._data: Dict[str, Any] = dict(initial or {})
        self._lock = RLock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._data.get(key)

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def exists(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def keys(self, prefix: str = "") -> Iterable[str]:
        with self._lock:
            if not prefix:
                return list(self._data.keys())
            return [k for k in self._data.keys() if k.startswith(prefix)]

    def begin_batch(self) -> WalletBatch:
        return _MemoryBatch(self)
