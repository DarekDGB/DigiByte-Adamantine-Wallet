import pytest

from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.state import WalletState
from core.wallet.sync import UTXO
from core.wallet.tx.builder import build_unsigned_tx, TxBuildError


def test_build_unsigned_tx_creates_change_output() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    # Total 6000 sats available
    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=1000, address=acc.receive_address_at(0)),
        UTXO(txid="bb" * 32, vout=1, value_sats=5000, address=acc.receive_address_at(1)),
    ]

    to_addr = "D" + "X" * 25  # dummy format; builder doesn't validate address yet
    utx = build_unsigned_tx(
        utxos=utxos,
        to_address=to_addr,
        amount_sats=2000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    # Should have 1 recipient + 1 change
    assert len(utx.outputs) == 2
    assert utx.outputs[0].address == to_addr
    assert utx.outputs[0].value_sats == 2000

    # Change = 6000 - 2000 - 500 = 3500
    assert utx.outputs[1].value_sats == 3500
    assert utx.fee_sats == 500


def test_build_unsigned_tx_no_change_if_below_dust() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=3000, address=acc.receive_address_at(0)),
    ]

    to_addr = "D" + "Y" * 25
    utx = build_unsigned_tx(
        utxos=utxos,
        to_address=to_addr,
        amount_sats=2500,
        fee_sats=500,
        account=acc,
        state=state,
        change_min_sats=600,  # force "no change" (3000-2500-500 = 0)
    )

    assert len(utx.outputs) == 1
    assert utx.outputs[0].address == to_addr
    assert utx.outputs[0].value_sats == 2500


def test_build_unsigned_tx_raises_on_bad_amount() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    with pytest.raises(TxBuildError):
        build_unsigned_tx(
            utxos=[],
            to_address="D" + "Z" * 25,
            amount_sats=0,
            fee_sats=0,
            account=acc,
            state=state,
        )
