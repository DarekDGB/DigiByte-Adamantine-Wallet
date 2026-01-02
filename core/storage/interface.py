"""
Storage Interface — Adamantine Wallet OS

Author: DarekDGB
License: MIT (see root LICENSE)

Goal:
- Database-agnostic storage
- Atomic batch writes (WalletBatch style)
- Namespaced keys to avoid collisions (DD_*, EQC_*, WSQK_* ...)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Protocol


# -------------------------
# Key namespacing helpers
# -------------------------

@dataclass(frozen=True)
class KeyNS:
    """
    Simple namespacing helper.
    Example:
        KeyNS("DD").k("BALANCE:addr") -> "DD_BALANCE:addr"
    """
    prefix: str

    def k(self, suffix: str) -> str:
        p = self.prefix.strip().upper()
        if not p:
            raise ValueError("KeyNS.prefix must be non-empty")
        return f"{p}_{suffix}"


# -------------------------
# Storage batch abstraction
# -------------------------

class WalletBatch(AbstractContextManager["WalletBatch"], ABC):
    """
    Atomic batch of writes/deletes.
    Implementations MUST guarantee:
    - commit() applies all changes atomically
    - rollback() applies none
    """

    @abstractmethod
    def put(self, key: str, value: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete(self, key: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def commit(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def rollback(self) -> None:
        raise NotImplementedError

    def __exit__(self, exc_type, exc, tb) -> bool:
        # If an exception happened, rollback; otherwise commit.
        if exc_type is not None:
            self.rollback()
            return False  # re-raise exception
        self.commit()
        return False


# -------------------------
# Storage interface
# -------------------------

class WalletStorage(ABC):
    """
    Database-agnostic wallet storage.

    This is intentionally minimal.
    Higher layers (wallet state, DD state, risk engine, etc.) should store
    their own serialized objects under namespaced keys.
    """

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Return value for key, or None if missing."""
        raise NotImplementedError

    @abstractmethod
    def put(self, key: str, value: Any) -> None:
        """Set value for key (non-batched)."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete key (no-op if missing)."""
        raise NotImplementedError

    @abstractmethod
    def exists(self, key: str) -> bool:
        """True if key exists."""
        raise NotImplementedError

    @abstractmethod
    def keys(self, prefix: str = "") -> Iterable[str]:
        """Iterate keys optionally filtered by prefix."""
        raise NotImplementedError

    @abstractmethod
    def begin_batch(self) -> WalletBatch:
        """Start an atomic batch."""
        raise NotImplementedError
