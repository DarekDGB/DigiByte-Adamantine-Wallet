"""
Query API (Read-only) — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Read-only helper APIs for clients (mobile/web/desktop)
- No signing, no mutation, no network
- Pure queries over persisted state
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from core.storage.interface import WalletStorage, KeyNS
from core.wallet.account_store import AccountStore, AccountState
from core.wallet.state_store import WalletStateStore, WalletState
from core.dd.dd_store import DDStore, DDPosition, DDBalance


ACCOUNT_NS = KeyNS("ACCOUNT")


@dataclass(frozen=True)
class WalletSummary:
    wallet_id: str
    label: Optional[str]
    account_count: int
    watch_only_count: int


class WalletQueryAPI:
    """
    Read-only API for client layers.
    """

    def __init__(self, storage: WalletStorage) -> None:
        self._storage = storage
        self._wallets = WalletStateStore(storage)
        self._accounts = AccountStore(storage)
        self._dd = DDStore(storage)

    # -------------------------
    # Wallets
    # -------------------------

    def get_wallet(self, wallet_id: str) -> Optional[WalletState]:
        return self._wallets.load(wallet_id)

    def wallet_exists(self, wallet_id: str) -> bool:
        return self._wallets.exists(wallet_id)

    def list_accounts(self, wallet_id: str) -> List[AccountState]:
        """
        List all accounts for a wallet by scanning ACCOUNT_ keys.
        """
        prefix = ACCOUNT_NS.k(f"{wallet_id}:")
        out: List[AccountState] = []
        for k in self._storage.keys(prefix=prefix):
            raw = self._storage.get(k)
            if raw is not None:
                out.append(AccountState(**raw))
        # stable order: by index then account_id
        out.sort(key=lambda a: (a.index, a.account_id))
        return out

    def get_wallet_summary(self, wallet_id: str) -> WalletSummary:
        wallet = self._wallets.load(wallet_id)
        accounts = self.list_accounts(wallet_id)
        watch_only = sum(1 for a in accounts if a.watch_only)
        return WalletSummary(
            wallet_id=wallet_id,
            label=getattr(wallet, "label", None) if wallet else None,
            account_count=len(accounts),
            watch_only_count=watch_only,
        )

    # -------------------------
    # DigiDollar (read-only)
    # -------------------------

    def list_dd_positions(self) -> List[DDPosition]:
        return list(self._dd.iter_positions())

    def list_dd_balances(self, wallet_id: str, account_id: str) -> List[DDBalance]:
        return list(self._dd.iter_balances(wallet_id, account_id))
