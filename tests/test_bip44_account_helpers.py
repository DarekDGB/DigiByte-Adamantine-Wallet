from core.wallet.keys.hd import (
    HDNode,
    derive_bip44_purpose,
    derive_bip44_coin,
    derive_bip44_account,
    bip44_account_path,
    BIP32Error,
)


def test_bip44_helpers_depths_and_child_numbers():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    n44 = derive_bip44_purpose(root)
    assert n44.depth == 1
    assert n44.child_number == (44 + 0x80000000)

    ncoin = derive_bip44_coin(root, 0)
    assert ncoin.depth == 2
    assert ncoin.child_number == (0 + 0x80000000)

    nacc = derive_bip44_account(root, 0, 0)
    assert nacc.depth == 3
    assert nacc.child_number == (0 + 0x80000000)


def test_bip44_account_path_is_hardened_only():
    p = bip44_account_path(coin_type=0, account=1)
    uints = p.to_uint32_list()
    assert uints == [44 + 0x80000000, 0 + 0x80000000, 1 + 0x80000000]


def test_invalid_coin_type_raises():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    try:
        derive_bip44_coin(root, -1)
        assert False, "Expected BIP32Error"
    except BIP32Error:
        pass
