"""
Wallet (UX core)

This is the minimal user-facing layer:
- get_receive_address(): returns current receive address (does NOT advance)
- next_receive_address(): advances receive_index and returns new address

No networking. No signing. No secrets stored in state.
"""

from __future__ import annotations

from dataclasses import replace

from .account import WalletAccount
from .keys.hdnode import HDNode
from .state import WalletState


class Wallet:
    def __init__(self, root: HDNode, state: WalletState | None = None) -> None:
        self._root = root
        self._state = state or WalletState()

    @property
    def state(self) -> WalletState:
        return self._state

    @property
    def account(self) -> WalletAccount:
        return WalletAccount(
            root=self._root,
            coin_type=self._state.coin_type,
            account=self._state.account,
        )

    def get_receive_address(self) -> str:
        # IMPORTANT: does NOT advance
        return self.account.receive_address_at(self._state.receive_index)

    def next_receive_address(self) -> str:
        # Advance then return the new address
        new_index = self._state.receive_index + 1
        self._state = replace(self._state, receive_index=new_index)
        return self.account.receive_address_at(self._state.receive_index)

    def get_change_address(self) -> str:
        # Optional helper (does NOT advance)
        return self.account.change_address_at(self._state.change_index)

    def next_change_address(self) -> str:
        new_index = self._state.change_index + 1
        self._state = replace(self._state, change_index=new_index)
        return self.account.change_address_at(self._state.change_index)
