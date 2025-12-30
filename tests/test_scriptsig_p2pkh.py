from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.state import WalletState
from core.wallet.sync import UTXO
from core.wallet.tx.builder import build_unsigned_tx
from core.wallet.tx.scriptsig import build_p2pkh_scriptsig


def test_build_p2pkh_scriptsig_structure() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    addr = acc.receive_address_at(0)
    utxos = [UTXO(txid="aa"*32, vout=0, value_sats=5000, address=addr)]

    unsigned = build_unsigned_tx(
        utxos=utxos,
        to_address="D" + "Z"*25,
        amount_sats=3000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    node = acc.derive_receive_node(0)
    priv = bytes.fromhex(node.private_key_hex)
    pub = node.pubkey(compressed=True)

    script = build_p2pkh_scriptsig(unsigned, 0, priv, pub)

    # Basic sanity checks
    assert isinstance(script, bytes)
    assert len(script) > 70          # sig + pubkey
    assert script[0] < 75            # push opcode
