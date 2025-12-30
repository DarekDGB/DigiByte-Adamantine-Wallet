from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.wallet.state import WalletState
from core.wallet.state_apply import apply_sync_result


@dataclass(frozen=True)
class FakeSyncResult:
    receive_last_used: Optional[int] = None
    change_last_used: Optional[int] = None


def test_apply_sync_result_advances_receive_index() -> None:
    state = WalletState(receive_index=0, change_index=0)
    res = FakeSyncResult(receive_last_used=5)

    new_state = apply_sync_result(state, res)
    assert new_state.receive_index == 6
    assert new_state.change_index == 0


def test_apply_sync_result_does_not_move_receive_backward() -> None:
    state = WalletState(receive_index=10, change_index=0)
    res = FakeSyncResult(receive_last_used=5)

    new_state = apply_sync_result(state, res)
    assert new_state.receive_index == 10


def test_apply_sync_result_none_does_not_change() -> None:
    state = WalletState(receive_index=3, change_index=7)
    res = FakeSyncResult(receive_last_used=None, change_last_used=None)

    new_state = apply_sync_result(state, res)
    assert new_state == state


def test_apply_sync_result_is_idempotent() -> None:
    state = WalletState(receive_index=0, change_index=0)
    res = FakeSyncResult(receive_last_used=2, change_last_used=4)

    s1 = apply_sync_result(state, res)
    s2 = apply_sync_result(s1, res)

    assert s1.receive_index == 3
    assert s1.change_index == 5
    assert s2 == s1
