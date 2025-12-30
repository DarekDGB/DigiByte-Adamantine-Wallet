from core.wallet.tx.sighash import legacy_sighash_all, SIGHASH_ALL
from core.wallet.tx.script import script_pubkey_p2pkh
from core.wallet.address import hash160
from core.wallet.tx.models import UnsignedTransaction, TxInput, TxOutput


def test_legacy_sighash_all_is_deterministic() -> None:
    pubkey = b"\x02" + b"\x11" * 32
    h160 = hash160(pubkey)

    unsigned = UnsignedTransaction(
        version=1,
        inputs=[
            TxInput(
                txid="aa" * 32,
                vout=0,
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            TxOutput(
                value_sats=1000,
                script_pubkey=script_pubkey_p2pkh(h160),
            )
        ],
        locktime=0,
    )

    h1 = legacy_sighash_all(unsigned, 0, pubkey)
    h2 = legacy_sighash_all(unsigned, 0, pubkey)

    assert isinstance(h1, bytes)
    assert len(h1) == 32
    assert h1 == h2
