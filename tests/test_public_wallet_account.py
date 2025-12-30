from core.wallet.account import WalletAccount
from core.wallet.keys.hd import HDNode
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.secp256k1 import pubkey_from_privkey
from core.wallet.public_account import PublicWalletAccount


def _hex_to_bytes(h: str, expected_len: int) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
    return b


def test_public_wallet_account_matches_private_addresses() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Private wallet
    root_priv = HDNode.from_seed(seed)
    acc_priv = WalletAccount(root=root_priv, coin_type=20, account=0)

    # Build account-level private node
    acct_node_priv = acc_priv._account_node()

    acct_chain_code = _hex_to_bytes(acct_node_priv.chain_code_hex, 32)
    acct_privkey = _hex_to_bytes(acct_node_priv.private_key_hex, 32)
    acct_pubkey = pubkey_from_privkey(acct_privkey, compressed=True)

    # Watch-only account
    acct_pub = PublicHDNode(
        chain_code=acct_chain_code,
        public_key=acct_pubkey,
        depth=acct_node_priv.depth,
        child_num=acct_node_priv.child_number,
        parent_fingerprint=_hex_to_bytes(acct_node_priv.parent_fingerprint_hex, 4),
        path="m/44'/20'/0'",
    )

    acc_pub = PublicWalletAccount(root=acct_pub, coin_type=20, account=0)

    # Receive addresses must match
    assert acc_pub.receive_address_at(0) == acc_priv.receive_address_at(0)
    assert acc_pub.receive_address_at(1) == acc_priv.receive_address_at(1)

    # Change addresses must match
    assert acc_pub.change_address_at(0) == acc_priv.change_address_at(0)
    assert acc_pub.change_address_at(1) == acc_priv.change_address_at(1)
