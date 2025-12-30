from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.state import WalletState
from core.wallet.sync import UTXO
from core.wallet.tx.builder import build_unsigned_tx
from core.wallet.tx.sighash import legacy_sighash_all


def test_legacy_sighash_all_is_deterministic() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    # Fund from a known receive address (index 0)
    a0 = acc.receive_address_at(0)
    utxos = [UTXO(txid="aa" * 32, vout=0, value_sats=5000, address=a0)]

    unsigned = build_unsigned_tx(
        utxos=utxos,
        to_address="D" + "Z" * 25,
        amount_sats=3000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    # pubkey for the input being signed comes from the same derived node
    node0 = acc.derive_receive_node(0)

    # Support both node styles (bytes privkey OR hex privkey)
    priv = getattr(node0, "private_key", None)
    if isinstance(priv, (bytes, bytearray)):
        priv_bytes = bytes(priv)
    else:
        priv_bytes = bytes.fromhex(getattr(node0, "private_key_hex"))

    from core.wallet.keys.secp256k1 import pubkey_from_privkey

    pubkey = pubkey_from_privkey(priv_bytes, compressed=True)

    h1 = legacy_sighash_all(unsigned, 0, pubkey)
    h2 = legacy_sighash_all(unsigned, 0, pubkey)

    assert isinstance(h1, bytes)
    assert len(h1) == 32
    assert h1 == h2
