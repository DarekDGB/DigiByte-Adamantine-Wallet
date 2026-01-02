"""
Wallet State Store — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Single place for reading/writing wallet state
- Storage-backed but backend-agnostic
- No business logic, only persistence boundaries
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from core.storage.interface import WalletStorage, KeyNS


WALLET_NS = KeyNS("WALLET")


@dataclass
class WalletState:
    """
    Minimal persisted wallet state.

    This is intentionally small.
    More fields can be added later without breaking storage.
    """
    wallet_id: str
    created_at: int
    version: int = 1
    label: Optional[str] = None


class WalletStateStore:
    """
    Storage-backed access to wallet state.
    """

    def __init__(self, storage: WalletStorage) -> None:
        self._storage = storage

    def _key(self, wallet_id: str) -> str:
        return WALLET_NS.k(f"STATE:{wallet_id}")

    def exists(self, wallet_id: str) -> bool:
        return self._storage.exists(self._key(wallet_id))

    def load(self, wallet_id: str) -> Optional[WalletState]:
        raw = self._storage.get(self._key(wallet_id))
        if raw is None:
            return None
        return WalletState(**raw)

    def save(self, state: WalletState) -> None:
        self._storage.put(self._key(state.wallet_id), asdict(state))

    def delete(self, wallet_id: str) -> None:
        self._storage.delete(self._key(wallet_id))
