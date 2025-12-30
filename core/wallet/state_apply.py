"""
WalletState apply helpers.

Goal:
- Apply a SyncResult-like object to WalletState
- Indices must be MONOTONIC (never move backwards)
- No secrets stored, no network calls, pure logic
"""

from __future__ import annotations

from typing import Optional, Protocol

from core.wallet.state import WalletState


class _HasLastUsed(Protocol):
    receive_last_used: Optional[int]
    change_last_used: Optional[int]


def _next_index(current: int, last_used: Optional[int]) -> int:
    """
    If last_used is None -> keep current
    Else -> at least last_used + 1 (but never decrease)
    """
    if last_used is None:
        return current
    # last_used is an index that was used; next should be +1
    candidate = last_used + 1
    return current if current >= candidate else candidate


def apply_sync_result(state: WalletState, result: _HasLastUsed) -> WalletState:
    """
    Return a NEW WalletState with indices advanced based on sync results.

    Rules:
    - receive_index advances to max(current, receive_last_used + 1)
    - change_index advances to max(current, change_last_used + 1)
    - if last_used is None, index is unchanged
    """
    new_receive = _next_index(state.receive_index, result.receive_last_used)
    new_change = _next_index(state.change_index, result.change_last_used)

    if new_receive == state.receive_index and new_change == state.change_index:
        return state

    return WalletState(
        network=state.network,
        coin_type=state.coin_type,
        account=state.account,
        receive_index=new_receive,
        change_index=new_change,
        gap_limit=state.gap_limit,
    )
