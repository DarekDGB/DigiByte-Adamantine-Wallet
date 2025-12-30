from core.wallet.keys.hd import HDNode
from core.wallet.account import WalletAccount
from core.wallet.state import WalletState
from core.wallet.sync import UTXO

from core.wallet.tx.builder import build_unsigned_tx
from core.wallet.tx.scriptsig import build_p2pkh_scriptsig
from core.wallet.tx.serialize import (
    SignedInput,
    SignedOutput,
    SignedTransaction,
    serialize_signed_tx_hex,
)
from core.wallet.tx.broadcast import FakeBroadcaster


def test_end_to_end_send_flow_builds_rawtx_and_broadcasts() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    # fund from receive index 0
    from_addr = acc.receive_address_at(0)
    utxos = [UTXO(txid="aa" * 32, vout=0, value_sats=5000, address=from_addr)]

    unsigned = build_unsigned_tx(
        utxos=utxos,
        to_address="D" + "Z" * 25,   # dummy destination, format only
        amount_sats=3000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    # derive privkey for the funded input (receive index 0)
    node0 = acc.derive_receive_node(0)
    priv = bytes.fromhex(node0.private_key_hex)

    from core.wallet.keys.secp256k1 import pubkey_from_privkey
    pub = pubkey_from_privkey(priv, compressed=True)

    # build scriptsig for input 0
    scriptsig0 = build_p2pkh_scriptsig(unsigned, 0, priv, pub)

    # build a signed transaction container
    signed = SignedTransaction(
        version=1,
        inputs=[
            SignedInput(
                txid=utxos[0].txid,
                vout=utxos[0].vout,
                script_sig=scriptsig0,
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            # builder outputs are address/value; convert into script_pubkey bytes
            SignedOutput(
                value_sats=unsigned.outputs[0].value_sats,
                script_pubkey=unsigned.outputs[0].script_pubkey,
            ),
            SignedOutput(
                value_sats=unsigned.outputs[1].value_sats,
                script_pubkey=unsigned.outputs[1].script_pubkey,
            ),
        ],
        locktime=0,
    )

    rawhex = serialize_signed_tx_hex(signed)

    # sanity: looks like a raw tx
    assert isinstance(rawhex, str)
    assert len(rawhex) > 100
    assert rawhex.startswith("01000000")  # version=1 little-endian

    # broadcast boundary
    b = FakeBroadcaster(accept=True, fake_txid="11" * 32)
    txid = b.broadcast_rawtx(rawhex)
    assert txid == "11" * 32
