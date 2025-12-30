from core.wallet.tx.serialize import (
    SignedInput,
    SignedOutput,
    SignedTransaction,
    serialize_signed_tx,
)
from core.wallet.tx.script import script_pubkey_p2pkh
from core.wallet.address import hash160


def test_serialize_signed_tx_is_deterministic() -> None:
    # fake 33-byte pubkey
    pub = b"\x02" + b"\x11" * 32
    h160 = hash160(pub)
    spk = script_pubkey_p2pkh(h160)

    tx = SignedTransaction(
        version=1,
        inputs=[
            SignedInput(
                txid="aa" * 32,
                vout=0,
                script_sig=b"\x01\x00",  # tiny placeholder
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            SignedOutput(
                value_sats=1000,
                script_pubkey=spk,
            )
        ],
        locktime=0,
    )

    b1 = serialize_signed_tx(tx)
    b2 = serialize_signed_tx(tx)
    assert b1 == b2
    assert len(b1) > 60  # sanity
    assert b1[:4] == (1).to_bytes(4, "little")  # version
