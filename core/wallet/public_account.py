from __future__ import annotations

from dataclasses import dataclass

from core.wallet.bridge import address_from_pubkey
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.public_derive import derive_child_public


@dataclass(frozen=True)
class PublicWalletAccount:
    """
    Watch-only wallet account.

    This mirrors WalletAccount but:
    - uses PublicHDNode
    - supports address derivation only
    - cannot sign or access private keys

    IMPORTANT:
    root MUST already be at account level:
    m/44'/coin_type'/account'
    """
    root: PublicHDNode
    coin_type: int = 20
    account: int = 0

    def _account_node(self) -> PublicHDNode:
        # For watch-only, the root is already the account node
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
        return address_from_pubkey(node.public_key)

    def change_address_at(self, index: int) -> str:
        node = self.derive_change_node(index)
        return address_from_pubkey(node.public_key)
