from core.wallet.keys.hd import DerivationPath, bip44_path, HDPathError


def test_parse_root():
    p = DerivationPath.parse("m")
    assert p.to_uint32_list() == []


def test_parse_simple_path():
    p = DerivationPath.parse("m/44'/0'/0'/0/0")
    uints = p.to_uint32_list()
    assert uints[0] == 44 + 0x80000000
    assert uints[1] == 0 + 0x80000000
    assert uints[2] == 0 + 0x80000000
    assert uints[3] == 0
    assert uints[4] == 0


def test_bip44_builder():
    p = bip44_path(coin_type=0, account=1, change=0, address_index=5)
    assert p.to_uint32_list()[0] == 44 + 0x80000000
    assert p.to_uint32_list()[1] == 0 + 0x80000000
    assert p.to_uint32_list()[2] == 1 + 0x80000000
    assert p.to_uint32_list()[3] == 0
    assert p.to_uint32_list()[4] == 5


def test_invalid_paths():
    for bad in ("", "n/44'/0'/0'", "m//0", "m/abc", "m/44'//0"):
        try:
            DerivationPath.parse(bad)
            assert False, f"Expected HDPathError for: {bad}"
        except HDPathError:
            pass
