import pytest

from core.wallet.tx.models import (
    OutPoint,
    TxInput,
    TxOutput,
    UnsignedTransaction,
    TxModelError,
)


def test_unsigned_tx_sanity_ok() -> None:
    op = OutPoint(txid="aa" * 32, vout=0)
    txin = TxInput(prevout=op, value_sats=10_000, address="DUMMY")
    txout = TxOutput(address="DUMMY2", value_sats=8_000)

    utx = UnsignedTransaction(inputs=[txin], outputs=[txout], fee_sats=1_000)
    utx.sanity_check()
    assert utx.total_in() == 10_000
    assert utx.total_out() == 8_000


def test_unsigned_tx_insufficient_raises() -> None:
    op = OutPoint(txid="bb" * 32, vout=1)
    txin = TxInput(prevout=op, value_sats=5_000, address="DUMMY")
    txout = TxOutput(address="DUMMY2", value_sats=5_000)

    utx = UnsignedTransaction(inputs=[txin], outputs=[txout], fee_sats=1)
    with pytest.raises(TxModelError):
        utx.sanity_check()
