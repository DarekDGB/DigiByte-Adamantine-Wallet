from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.state import WalletState
from core.wallet.sync import UTXO

from core.wallet.tx.plan import make_send_plan


def test_send_plan_with_change() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=1000, address=acc.receive_address_at(0)),
        UTXO(txid="bb" * 32, vout=1, value_sats=5000, address=acc.receive_address_at(1)),
    ]

    to_addr = "D" + "X" * 25
    plan, utx = make_send_plan(
        utxos=utxos,
        to_address=to_addr,
        amount_sats=2000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    assert plan.total_in_sats == 6000
    assert plan.fee_sats == 500
    assert plan.amount_sats == 2000
    assert plan.change_sats == 3500
    assert plan.input_count == 2
    assert plan.output_count == 2
    assert plan.change_address is not None

    # tx output matches plan
    assert utx.outputs[0].address == to_addr
    assert utx.outputs[0].value_sats == 2000


def test_send_plan_no_change() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=3000, address=acc.receive_address_at(0)),
    ]

    to_addr = "D" + "Y" * 25
    plan, utx = make_send_plan(
        utxos=utxos,
        to_address=to_addr,
        amount_sats=2500,
        fee_sats=500,
        account=acc,
        state=state,
        change_min_sats=600,
    )

    assert plan.total_in_sats == 3000
    assert plan.change_sats == 0
    assert plan.change_address is None
    assert plan.output_count == 1
    assert len(utx.outputs) == 1
