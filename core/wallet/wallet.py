"""
Wallet (UX core)

Minimal user-facing layer:
- get_receive_address(): returns current receive address (does NOT advance)
- next_receive_address(): advances receive_index and returns new address

No networking. No signing. No secrets stored in state.
"""

from __future__ import annotations

from dataclasses import replace

from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode as HDPrivNode
from core.wallet.state import WalletState


class Wallet:
    def __init__(self, root: HDPrivNode, state: WalletState | None = None) -> None:
        self._root = root
        self._state = state or WalletState()

    @property
    def state(self) -> WalletState:
        return self._state

    def _account(self) -> WalletAccount:
        acc = WalletAccount(
            root=self._root,
            coin_type=self._state.coin_type,
            account=self._state.account,
            gap_limit=self._state.gap_limit,
        )
        acc.receive_index = self._state.receive_index
        acc.change_index = self._state.change_index
        return acc

    def get_receive_address(self) -> str:
        # IMPORTANT: does NOT advance
        return self._account().receive_address_at(self._state.receive_index)

    def next_receive_address(self) -> str:
        # Advance then return the new address
        new_index = self._state.receive_index + 1
        self._state = replace(self._state, receive_index=new_index)
        return self._account().receive_address_at(self._state.receive_index)

    def get_change_address(self) -> str:
        return self._account().change_address_at(self._state.change_index)

    def next_change_address(self) -> str:
        new_index = self._state.change_index + 1
        self._state = replace(self._state, change_index=new_index)
        return self._account().change_address_at(self._state.change_index)
