import pytest

from core.wallet.sync import UTXO
from core.wallet.tx.selector import select_utxos_smallest_first, CoinSelectionError


def test_select_utxos_smallest_first_picks_smallest() -> None:
    utxos = [
        UTXO(txid="cc" * 32, vout=0, value_sats=5000, address="A"),
        UTXO(txid="aa" * 32, vout=1, value_sats=2000, address="A"),
        UTXO(txid="bb" * 32, vout=2, value_sats=3000, address="A"),
    ]

    sel = select_utxos_smallest_first(utxos, target_sats=4000, fee_sats=500)

    # Need 4500 -> should pick 2000 + 3000 (not 5000)
    assert [u.value_sats for u in sel.selected] == [2000, 3000]
    assert sel.total_selected_sats == 5000


def test_select_utxos_raises_on_insufficient() -> None:
    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=1000, address="A"),
    ]
    with pytest.raises(CoinSelectionError):
        select_utxos_smallest_first(utxos, target_sats=2000, fee_sats=0)
