from __future__ import annotations

from typing import List, Optional

from core.wallet.account import WalletAccount
from core.wallet.state import WalletState
from core.wallet.sync import UTXO
from core.wallet.tx.models import OutPoint, TxInput, TxOutput, UnsignedTransaction
from core.wallet.tx.selector import Selection, select_utxos_smallest_first


class TxBuildError(ValueError):
    pass


def build_unsigned_tx(
    *,
    utxos: List[UTXO],
    to_address: str,
    amount_sats: int,
    fee_sats: int,
    account: WalletAccount,
    state: WalletState,
    change_min_sats: int = 546,  # dust-ish floor (placeholder)
) -> UnsignedTransaction:
    """
    Build an unsigned transaction:
    - select coins deterministically
    - output to recipient
    - add change output to current change address if needed

    No signing. No broadcasting. Pure builder.

    IMPORTANT:
    - This does not mutate state.
    - Caller may later advance change_index after signing/broadcasting success.
    """
    if amount_sats <= 0:
        raise TxBuildError("amount_sats must be > 0")
    if fee_sats < 0:
        raise TxBuildError("fee_sats must be >= 0")
    if not to_address:
        raise TxBuildError("to_address required")

    sel: Selection = select_utxos_smallest_first(utxos, target_sats=amount_sats, fee_sats=fee_sats)
    change_sats = sel.change_sats(amount_sats + fee_sats)

    # Inputs
    inputs: List[TxInput] = [
        TxInput(
            prevout=OutPoint(txid=u.txid, vout=u.vout),
            value_sats=u.value_sats,
            address=u.address,
        )
        for u in sel.selected
    ]

    # Outputs: recipient
    outputs: List[TxOutput] = [TxOutput(address=to_address, value_sats=amount_sats)]

    # Optional change output (only if above dust floor)
    if change_sats >= change_min_sats:
        change_addr = account.change_address_at(state.change_index)
        outputs.append(TxOutput(address=change_addr, value_sats=change_sats))

    utx = UnsignedTransaction(inputs=inputs, outputs=outputs, fee_sats=fee_sats)
    utx.sanity_check()
    return utx
