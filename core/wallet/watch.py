"""
Watch-only scaffolding.

This module defines a minimal public-only account interface:
- Can generate/represent addresses
- Cannot access private keys
- Cannot sign

xpub support will be added later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, Sequence


class WatchOnlyError(ValueError):
    pass


class PubkeyDeriver(Protocol):
    """
    Contract for a public-only derivation engine (xpub/CKDpub later).
    """

    def pubkey_at(self, change: int, index: int) -> bytes: ...


@dataclass
class WatchOnlyAccount:
    """
    Public-only account wrapper.

    For now, we accept a `pubkey_deriver` that can give a pubkey at (change, index).
    Later we will implement a real xpub-based deriver.

    change:
      0 = external (receive)
      1 = internal (change)
    """

    pubkey_deriver: PubkeyDeriver
    gap_limit: int = 20

    def __post_init__(self) -> None:
        if self.gap_limit <= 0:
            raise WatchOnlyError("gap_limit must be > 0")

    def can_sign(self) -> bool:
        return False

    def receive_pubkey(self, index: int) -> bytes:
        return self.pubkey_deriver.pubkey_at(0, index)

    def change_pubkey(self, index: int) -> bytes:
        return self.pubkey_deriver.pubkey_at(1, index)
