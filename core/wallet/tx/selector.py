from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from core.wallet.sync import UTXO


class CoinSelectionError(ValueError):
    pass


@dataclass(frozen=True)
class Selection:
    selected: List[UTXO]
    total_selected_sats: int

    def change_sats(self, target_plus_fee_sats: int) -> int:
        return self.total_selected_sats - target_plus_fee_sats


def select_utxos_smallest_first(
    utxos: List[UTXO],
    target_sats: int,
    fee_sats: int,
) -> Selection:
    """
    Deterministic coin selection: pick smallest UTXOs first until target+fee met.

    Inputs:
    - utxos: list of available UTXOs
    - target_sats: amount to send (excluding fee)
    - fee_sats: fixed fee for now

    Returns:
    - Selection with selected utxos and total.

    Raises:
    - CoinSelectionError if insufficient funds or invalid params.
    """
    if target_sats <= 0:
        raise CoinSelectionError("target_sats must be > 0")
    if fee_sats < 0:
        raise CoinSelectionError("fee_sats must be >= 0")

    need = target_sats + fee_sats
    ordered = sorted(utxos, key=lambda u: (u.value_sats, u.txid, u.vout))

    chosen: List[UTXO] = []
    total = 0

    for u in ordered:
        if u.value_sats <= 0:
            continue
        chosen.append(u)
        total += u.value_sats
        if total >= need:
            return Selection(selected=chosen, total_selected_sats=total)

    raise CoinSelectionError("insufficient funds")
