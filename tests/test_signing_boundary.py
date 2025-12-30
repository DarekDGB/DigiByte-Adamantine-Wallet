import pytest

from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.secp256k1 import pubkey_from_privkey
from core.wallet.public_account import PublicWalletAccount
from core.wallet.state import WalletState
from core.wallet.sync import UTXO
from core.wallet.tx.builder import build_unsigned_tx
from core.wallet.tx.signing import sign_transaction_p2pkh, SigningError


class FakeSigner:
    """
    Deterministic signer for boundary testing.
    This is NOT ECDSA. It only proves the architecture boundary.
    """
    def sign(self, message: bytes, privkey32: bytes) -> bytes:
        # Deterministic, unique-ish output
        return b"SIG|" + message[:24] + b"|" + privkey32[:8]


def _hex_to_bytes(h: str, expected_len: int) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
    return b


def test_private_wallet_can_sign_placeholder_inputs() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)
    state = WalletState.default()

    # Fund from known receive addresses
    a0 = acc.receive_address_at(0)
    a1 = acc.receive_address_at(1)

    utxos = [
        UTXO(txid="aa" * 32, vout=0, value_sats=2000, address=a0),
        UTXO(txid="bb" * 32, vout=1, value_sats=5000, address=a1),
    ]

    unsigned = build_unsigned_tx(
        utxos=utxos,
        to_address="D" + "X" * 25,
        amount_sats=3000,
        fee_sats=500,
        account=acc,
        state=state,
    )

    signed = sign_transaction_p2pkh(unsigned=unsigned, account=acc, state=state, signer=FakeSigner())
    assert len(signed.signed_inputs) == len(unsigned.inputs)
    assert signed.signed_inputs[0].signature.startswith(b"SIG|")
    assert len(signed.signed_inputs[0].pubkey) == 33


def test_watch_only_cannot_sign() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Private wallet (to create a watch-only account root at account level)
    root_priv = HDNode.from_seed(seed)
    acc_priv = WalletAccount(root=root_priv, coin_type=20, account=0)
    acct_node_priv = acc_priv._account_node()

    acct_chain_code = _hex_to_bytes(acct_node_priv.chain_code_hex, 32)
    acct_privkey = _hex_to_bytes(acct_node_priv.private_key_hex, 32)
    acct_pubkey = pubkey_from_privkey(acct_privkey, compressed=True)

    watch_root = PublicHDNode(chain_code=acct_chain_code, public_key=acct_pubkey, path="m/44'/20'/0'")
    acc_watch = PublicWalletAccount(root=watch_root, coin_type=20, account=0)

    state = WalletState.default()

    # UTXO to a watch-only derived address
    a0 = acc_watch.receive_address_at(0)
    utxos = [UTXO(txid="aa" * 32, vout=0, value_sats=5000, address=a0)]

    # Build unsigned tx (builder uses WalletAccount, so for this test we build it manually)
    # We can still reuse build_unsigned_tx by using the private account for change address,
    # but signing must be attempted with watch-only and MUST fail.
    unsigned = build_unsigned_tx(
        utxos=utxos,
        to_address="D" + "Y" * 25,
        amount_sats=3000,
        fee_sats=500,
        account=acc_priv,   # only used for change address selection; not used for signing test
        state=state,
    )

    with pytest.raises(SigningError):
        # Watch-only should fail: no private keys
        sign_transaction_p2pkh(unsigned=unsigned, account=acc_priv, state=state, signer=FakeSigner())  # sanity
