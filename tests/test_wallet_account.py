import pytest

from core.wallet.keys.hd import HDNode
from core.wallet.account import WalletAccount


def test_wallet_account_indices_increment():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    acc = WalletAccount(root=root, coin_type=20, account=0)

    a0 = acc.next_receive_address()
    a1 = acc.next_receive_address()
    assert a0 != a1
    assert acc.receive_index == 2

    c0 = acc.next_change_address()
    c1 = acc.next_change_address()
    assert c0 != c1
    assert acc.change_index == 2


def test_wallet_account_address_format():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)

    addr = acc.receive_address_at(0)
    assert addr.startswith("D")
    assert 26 <= len(addr) <= 36


def test_wallet_account_gap_limit_validation():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    with pytest.raises(ValueError):
        WalletAccount(root=root, gap_limit=0)
