"""
WalletAccount: minimal account abstraction.

Responsibilities:
- Track address indices (external + internal)
- Derive nodes using existing HD core
- Produce DigiByte P2PKH addresses using bridge

Non-goals (later phases):
- UTXO scanning, gap-limit discovery
- Persistence (db/file)
- Multi-account wallet container
"""

from __future__ import annotations

from dataclasses import dataclass

from core.wallet.bridge import address_from_node
from core.wallet.keys.hd import HDNode as HDPrivNode, derive_bip44_account, derive_bip44_address


@dataclass
class WalletAccount:
    """
    Minimal BIP44 account manager.

    coin_type:
      - DigiByte (SLIP-0044) is typically 20.
    """
    root: HDPrivNode
    coin_type: int = 20
    account: int = 0
    gap_limit: int = 20

    receive_index: int = 0  # m/.../0/i
    change_index: int = 0   # m/.../1/i

    def __post_init__(self) -> None:
        if self.gap_limit <= 0:
            raise ValueError("gap_limit must be > 0")
        if self.receive_index < 0 or self.change_index < 0:
            raise ValueError("indices must be >= 0")

    def _account_node(self) -> HDPrivNode:
        # m/44'/coin'/account'
        return derive_bip44_account(self.root, self.coin_type, self.account)

    def derive_receive_node(self, index: int) -> HDPrivNode:
        # m/44'/coin'/account'/0/index
        return derive_bip44_address(self._account_node(), change=0, index=index)

    def derive_change_node(self, index: int) -> HDPrivNode:
        # m/44'/coin'/account'/1/index
        return derive_bip44_address(self._account_node(), change=1, index=index)

    def receive_address_at(self, index: int) -> str:
        return address_from_node(self.derive_receive_node(index))

    def change_address_at(self, index: int) -> str:
        return address_from_node(self.derive_change_node(index))

    def next_receive_address(self) -> str:
        addr = self.receive_address_at(self.receive_index)
        self.receive_index += 1
        return addr

    def next_change_address(self) -> str:
        addr = self.change_address_at(self.change_index)
        self.change_index += 1
        return addr
