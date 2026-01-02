"""
Account Store — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Persist wallet account metadata
- Define watch-only accounts at data level
- Backend-agnostic via WalletStorage
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from core.storage.interface import WalletStorage, KeyNS


ACCOUNT_NS = KeyNS("ACCOUNT")


@dataclass
class AccountState:
    """
    Persisted account metadata.

    NOTE:
    - No keys stored here
    - No signing logic
    - Pure state only
    """
    wallet_id: str
    account_id: str
    index: int
    watch_only: bool = False
    label: Optional[str] = None


class AccountStore:
    """
    Storage-backed account state store.
    """

    def __init__(self, storage: WalletStorage) -> None:
        self._storage = storage

    def _key(self, wallet_id: str, account_id: str) -> str:
        return ACCOUNT_NS.k(f"{wallet_id}:{account_id}")

    def exists(self, wallet_id: str, account_id: str) -> bool:
        return self._storage.exists(self._key(wallet_id, account_id))

    def load(self, wallet_id: str, account_id: str) -> Optional[AccountState]:
        raw = self._storage.get(self._key(wallet_id, account_id))
        if raw is None:
            return None
        return AccountState(**raw)

    def save(self, state: AccountState) -> None:
        self._storage.put(self._key(state.wallet_id, state.account_id), asdict(state))

    def delete(self, wallet_id: str, account_id: str) -> None:
        self._storage.delete(self._key(wallet_id, account_id))

    def is_watch_only(self, wallet_id: str, account_id: str) -> bool:
        state = self.load(wallet_id, account_id)
        if state is None:
            return False
        return state.watch_only
