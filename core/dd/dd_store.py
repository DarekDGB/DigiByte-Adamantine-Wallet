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


@dataclass
class DDBalance:
    """
    Storage view of DD balance for an address or account scope.
    """
    wallet_id: str
    account_id: str
    address: str
    balance_minor: int


@dataclass
class DDOutput:
    """
    Storage view of a DD-related output (UTXO-style record).
    """
    txid: str
    vout: int
    wallet_id: str
    account_id: str
    address: str
    amount_minor: int
    is_spent: bool = False


# -------------------------
# DD Store
# -------------------------

class DDStore:
    """
    Storage-backed DigiDollar state store.
    """

    def __init__(self, storage: WalletStorage) -> None:
        self._storage = storage

    # ---- positions ----

    def _pos_key(self, position_id: str) -> str:
        return DD_NS.k(f"POSITION:{position_id}")

    def save_position(self, pos: DDPosition) -> None:
        self._storage.put(self._pos_key(pos.position_id), asdict(pos))

    def load_position(self, position_id: str) -> Optional[DDPosition]:
        raw = self._storage.get(self._pos_key(position_id))
        if raw is None:
            return None
        return DDPosition(**raw)

    def delete_position(self, position_id: str) -> None:
        self._storage.delete(self._pos_key(position_id))

    def iter_positions(self) -> Iterable[DDPosition]:
        prefix = DD_NS.k("POSITION:")
        for k in self._storage.keys(prefix=prefix):
            raw = self._storage.get(k)
            if raw is not None:
                yield DDPosition(**raw)

    # ---- balances ----

    def _bal_key(self, wallet_id: str, account_id: str, address: str) -> str:
        return DD_NS.k(f"BALANCE:{wallet_id}:{account_id}:{address}")

    def set_balance(self, bal: DDBalance) -> None:
        self._storage.put(self._bal_key(bal.wallet_id, bal.account_id, bal.address), asdict(bal))

    def get_balance(self, wallet_id: str, account_id: str, address: str) -> Optional[DDBalance]:
        raw = self._storage.get(self._bal_key(wallet_id, account_id, address))
        if raw is None:
            return None
        return DDBalance(**raw)

    def iter_balances(self, wallet_id: str, account_id: str) -> Iterable[DDBalance]:
        prefix = DD_NS.k(f"BALANCE:{wallet_id}:{account_id}:")
        for k in self._storage.keys(prefix=prefix):
            raw = self._storage.get(k)
            if raw is not None:
                yield DDBalance(**raw)

    # ---- outputs ----

    def _out_key(self, txid: str, vout: int) -> str:
        return DD_NS.k(f"OUTPUT:{txid}:{vout}")

    def save_output(self, out: DDOutput) -> None:
        self._storage.put(self._out_key(out.txid, out.vout), asdict(out))

    def load_output(self, txid: str, vout: int) -> Optional[DDOutput]:
        raw = self._storage.get(self._out_key(txid, vout))
        if raw is None:
            return None
        return DDOutput(**raw)

    def delete_output(self, txid: str, vout: int) -> None:
        self._storage.delete(self._out_key(txid, vout))

    def iter_outputs(self) -> Iterable[DDOutput]:
        prefix = DD_NS.k("OUTPUT:")
        for k in self._storage.keys(prefix=prefix):
            raw = self._storage.get(k)
            if raw is not None:
                yield DDOutput(**raw)
