"""
DD Storage — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Persist DigiDollar (DD) wallet-related state
- Namespaced storage (DD_*)
- No protocol or minting logic here
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Optional

from core.storage.interface import WalletStorage, KeyNS


DD_NS = KeyNS("DD")


# -------------------------
# Persisted DD structures
# -------------------------

@dataclass
class DDPosition:
    """
    Represents a single DigiDollar collateral position.

    NOTE:
    - This is storage-only
    - No validation or rules here
    """
    position_id: str
    wallet_id: str
    account_id: str
    dgb_collateral: int
    dd_minted: int
    lock_tier: int
    unlock_height: int
    is_active: bool = True


# -------------------------
# DD Store
# -------------------------

class DDStore:
    """
    Storage-backed DigiDollar state store.
    """

    def __init__(self, storage: WalletStorage) -> None:
        self._storage = storage

    def _key(self, position_id: str) -> str:
        return DD_NS.k(f"POSITION:{position_id}")

    def save_position(self, pos: DDPosition) -> None:
        self._storage.put(self._key(pos.position_id), asdict(pos))

    def load_position(self, position_id: str) -> Optional[DDPosition]:
        raw = self._storage.get(self._key(position_id))
        if raw is None:
            return None
        return DDPosition(**raw)

    def delete_position(self, position_id: str) -> None:
        self._storage.delete(self._key(position_id))

    def iter_positions(self) -> Iterable[DDPosition]:
        prefix = DD_NS.k("POSITION:")
        for k in self._storage.keys(prefix=prefix):
            raw = self._storage.get(k)
            if raw is not None:
                yield DDPosition(**raw)
