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
from core.wallet.tx.script import script_pubkey_p2pkh


def _h160_from_p2pkh_address(addr: str) -> bytes:
    """
    Decode DigiByte P2PKH Base58Check address to HASH160 payload (20 bytes).
    Works with whichever decode helper exists in core.wallet.address.
    """
    from core.wallet import address as addrmod

    # Option A: base58check_decode(addr) -> bytes(version + payload)
    if hasattr(addrmod, "base58check_decode"):
        b = addrmod.base58check_decode(addr)
        if len(b) < 21:
            raise ValueError("decoded address too short")
        return b[1:21]

    # Option B: decode_base58check(addr) -> (version:int, payload:bytes)
    if hasattr(addrmod, "decode_base58check"):
        version, payload = addrmod.decode_base58check(addr)
        if len(payload) != 20:
            raise ValueError("unexpected payload length")
        return payload

    raise RuntimeError(
        "No base58check decoder found in core.wallet.address "
        "(expected base58check_decode or decode_base58check)"
    )


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

    # privkey for funded input (receive index 0)
    node0 = acc.derive_receive_node(0)
    priv = bytes.fromhex(node0.private_key_hex)

    from core.wallet.keys.secp256k1 import pubkey_from_privkey
    pub = pubkey_from_privkey(priv, compressed=True)

    # scriptSig for input 0
    scriptsig0 = build_p2pkh_scriptsig(unsigned, 0, priv, pub)

    # Convert builder TxOutput(address,value) -> SignedOutput(script_pubkey,value)
    out0_h160 = _h160_from_p2pkh_address(unsigned.outputs[0].address)
    out1_h160 = _h160_from_p2pkh_address(unsigned.outputs[1].address)

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
            SignedOutput(
                value_sats=unsigned.outputs[0].value_sats,
                script_pubkey=script_pubkey_p2pkh(out0_h160),
            ),
            SignedOutput(
                value_sats=unsigned.outputs[1].value_sats,
                script_pubkey=script_pubkey_p2pkh(out1_h160),
            ),
        ],
        locktime=0,
    )

    rawhex = serialize_signed_tx_hex(signed)

    assert isinstance(rawhex, str)
    assert len(rawhex) > 100
    assert rawhex.startswith("01000000")

    # broadcast boundary
    b = FakeBroadcaster(accept=True, fake_txid="11" * 32)
    txid = b.broadcast_rawtx(rawhex)
    assert txid == "11" * 32
