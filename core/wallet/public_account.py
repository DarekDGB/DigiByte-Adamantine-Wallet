from __future__ import annotations

from dataclasses import dataclass

from core.wallet.address import p2pkh_from_pubkey
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.public_derive import derive_child_public


@dataclass(frozen=True)
class PublicWalletAccount:
    """
    Watch-only wallet account.

    Mirrors WalletAccount but:
    - uses PublicHDNode + public derivation
    - can derive receive/change addresses
    - cannot sign

    IMPORTANT:
    root MUST already be at account level:
    m/44'/coin_type'/account'
    """
    root: PublicHDNode
    coin_type: int = 20
    account: int = 0

    def _account_node(self) -> PublicHDNode:
        return self.root

    def derive_receive_node(self, index: int) -> PublicHDNode:
        # m/.../0/index
        chain0 = derive_child_public(self._account_node(), 0)
        return derive_child_public(chain0, index)

    def derive_change_node(self, index: int) -> PublicHDNode:
        # m/.../1/index
        chain1 = derive_child_public(self._account_node(), 1)
        return derive_child_public(chain1, index)

    def receive_address_at(self, index: int) -> str:
        node = self.derive_receive_node(index)
        return p2pkh_from_pubkey(node.public_key)

    def change_address_at(self, index: int) -> str:
        node = self.derive_change_node(index)
        return p2pkh_from_pubkey(node.public_key)
