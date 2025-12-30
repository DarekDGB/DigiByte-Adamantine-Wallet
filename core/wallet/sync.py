from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, Optional

from .account import WalletAccount
from .state import WalletState
from .discovery import discover_used_indices, AddressDiscoveryProvider


@dataclass(frozen=True)
class UTXO:
    txid: str
    vout: int
    value_sats: int
    address: str


class WalletSyncProvider(AddressDiscoveryProvider, Protocol):
    """
    Future sync engines implement this contract (ElectrumX/Esplora/full node/etc).

    For now we only need:
    - is_used(address) -> bool
    - list_utxos(address) -> List[UTXO]
    """

    def list_utxos(self, address: str) -> List[UTXO]: ...


@dataclass
class SyncResult:
    balance_sats: int
    utxos: List[UTXO]
    receive_last_used: Optional[int]
    change_last_used: Optional[int]
    scanned_receive: int
    scanned_change: int


def sync_account(
    provider: WalletSyncProvider,
    account: WalletAccount,
    state: WalletState,
    max_scan: int = 2000,
) -> SyncResult:
    """
    Discover used addresses (receive + change) using gap-limit rules and
    collect UTXOs for discovered addresses.

    This does NOT broadcast, does NOT sign, and does NOT store secrets.
    """
    gap = state.gap_limit

    # Receive chain discovery
    recv = discover_used_indices(
        provider=provider,
        address_at_index=account.receive_address_at,
        gap_limit=gap,
        start_index=0,
        max_scan=max_scan,
    )

    # Change chain discovery
    chg = discover_used_indices(
        provider=provider,
        address_at_index=account.change_address_at,
        gap_limit=gap,
        start_index=0,
        max_scan=max_scan,
    )

    # Gather UTXOs for all indices scanned up to last used + gap window
    utxos: List[UTXO] = []
    balance = 0

    def collect_chain(address_at_index, last_used: Optional[int]) -> None:
        nonlocal balance, utxos
        if last_used is None:
            return
        # scan window: 0..(last_used + gap_limit - 1)
        end = last_used + gap
        for i in range(0, end + 1):
            addr = address_at_index(i)
            for u in provider.list_utxos(addr):
                utxos.append(u)
                balance += u.value_sats

    collect_chain(account.receive_address_at, recv.last_used_index)
    collect_chain(account.change_address_at, chg.last_used_index)

    return SyncResult(
        balance_sats=balance,
        utxos=utxos,
        receive_last_used=recv.last_used_index,
        change_last_used=chg.last_used_index,
        scanned_receive=recv.scanned_count,
        scanned_change=chg.scanned_count,
    )
