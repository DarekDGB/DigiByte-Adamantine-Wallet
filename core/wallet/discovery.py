"""
Gap-limit discovery scaffold.

This module defines a provider interface that *future sync engines* implement.
Right now it is only a contract + deterministic helper logic.

BIP44 discovery rule (high level):
- Scan addresses in order.
- Stop when you encounter `gap_limit` consecutive unused addresses.

No networking is implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Protocol


class AddressDiscoveryProvider(Protocol):
    """
    Implemented by future sync engines.

    Should return True if an address has ever been used on-chain
    (has transactions, UTXOs, history, etc).
    """

    def is_used(self, address: str) -> bool: ...


@dataclass(frozen=True)
class DiscoveryResult:
    used_indices: List[int]
    last_used_index: int | None
    scanned_count: int


def discover_used_indices(
    provider: AddressDiscoveryProvider,
    address_at_index,
    gap_limit: int = 20,
    start_index: int = 0,
    max_scan: int = 1000,
) -> DiscoveryResult:
    """
    Scan addresses starting at `start_index` and stop after `gap_limit`
    consecutive unused addresses, or after `max_scan` scans.

    `address_at_index(index) -> str` is provided by WalletAccount (receive or change).
    """
    if gap_limit <= 0:
        raise ValueError("gap_limit must be > 0")
    if start_index < 0:
        raise ValueError("start_index must be >= 0")
    if max_scan <= 0:
        raise ValueError("max_scan must be > 0")

    used: List[int] = []
    last_used: int | None = None
    unused_streak = 0
    scanned = 0

    idx = start_index
    while scanned < max_scan:
        addr = address_at_index(idx)
        scanned += 1

        if provider.is_used(addr):
            used.append(idx)
            last_used = idx
            unused_streak = 0
        else:
            unused_streak += 1
            if unused_streak >= gap_limit:
                break

        idx += 1

    return DiscoveryResult(used_indices=used, last_used_index=last_used, scanned_count=scanned)
