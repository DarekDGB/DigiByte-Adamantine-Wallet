"""
Account Factory — Adamantine Wallet OS

Author: DarekDGB
License: MIT

Purpose:
- Single canonical way to create wallet accounts
- Persist account metadata safely
- Avoid ad-hoc account creation logic across clients
"""

from __future__ import annotations

from typing import Optional

from core.wallet.account_store import AccountStore, AccountState


class AccountFactory:
    """
    Creates wallet accounts with consistent defaults.
    """

    def __init__(self, account_store: AccountStore) -> None:
        self._store = account_store

    def create_account(
        self,
        *,
        wallet_id: str,
        account_id: str,
        index: int,
        watch_only: bool = False,
        label: Optional[str] = None,
    ) -> AccountState:
        """
        Create and persist a new account.

        Rules:
        - account_id must be unique per wallet
        - watch-only accounts are explicitly marked
        """
        if self._store.exists(wallet_id, account_id):
            raise ValueError(f"Account already exists: {wallet_id}:{account_id}")

        state = AccountState(
            wallet_id=wallet_id,
            account_id=account_id,
            index=index,
            watch_only=watch_only,
            label=label,
        )

        self._store.save(state)
        return state
