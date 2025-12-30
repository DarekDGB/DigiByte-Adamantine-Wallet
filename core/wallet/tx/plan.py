from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from core.wallet.account import WalletAccount
from core.wallet.state import WalletState
from core.wallet.sync import UTXO

from core.wallet.tx.builder import build_unsigned_tx
from core.wallet.tx.models import UnsignedTransaction, TxOutput


@dataclass(frozen=True)
class WalletSendPlan:
    to_address: str
    amount_sats: int
    fee_sats: int

    total_in_sats: int
    change_sats: int

    input_count: int
    output_count: int

    change_address: Optional[str]


def _find_change_output(
    outputs: List[TxOutput],
    to_address: str,
    amount_sats: int,
) -> Tuple[int, Optional[str]]:
    """
    Return (change_sats, change_address).
    Assumes the recipient output is exactly (to_address, amount_sats).
    Any other output is treated as change (for this phase).
    """
    change_sats = 0
    change_addr: Optional[str] = None

    for o in outputs:
        if o.address == to_address and o.value_sats == amount_sats:
            continue
        change_sats += o.value_sats
        change_addr = o.address

    return change_sats, change_addr


def make_send_plan(
    *,
    utxos: List[UTXO],
    to_address: str,
    amount_sats: int,
    fee_sats: int,
    account: WalletAccount,
    state: WalletState,
    change_min_sats: int = 546,
) -> Tuple[WalletSendPlan, UnsignedTransaction]:
    """
    Produce a UX-friendly send plan AND the unsigned transaction.

    No signing. No broadcasting. No state mutation.
    """
    utx = build_unsigned_tx(
        utxos=utxos,
        to_address=to_address,
        amount_sats=amount_sats,
        fee_sats=fee_sats,
        account=account,
        state=state,
        change_min_sats=change_min_sats,
    )

    total_in = utx.total_in()
    change_sats, change_addr = _find_change_output(utx.outputs, to_address, amount_sats)

    plan = WalletSendPlan(
        to_address=to_address,
        amount_sats=amount_sats,
        fee_sats=fee_sats,
        total_in_sats=total_in,
        change_sats=change_sats,
        input_count=len(utx.inputs),
        output_count=len(utx.outputs),
        change_address=change_addr,
    )
    return plan, utx
