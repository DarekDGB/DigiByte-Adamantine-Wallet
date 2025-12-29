from core.wallet.keys.secp256k1 import pubkey_from_privkey, Gx, Gy


def test_pubkey_from_privkey_1_compressed():
    priv = (1).to_bytes(32, "big")
    pub = pubkey_from_privkey(priv, compressed=True)

    # Compressed pubkey: 02/03 + x
    x = Gx.to_bytes(32, "big")
    expected_prefix = b"\x02" if (Gy % 2 == 0) else b"\x03"
    assert pub == expected_prefix + x


def test_pubkey_from_privkey_1_uncompressed():
    priv = (1).to_bytes(32, "big")
    pub = pubkey_from_privkey(priv, compressed=False)

    x = Gx.to_bytes(32, "big")
    y = Gy.to_bytes(32, "big")
    assert pub == b"\x04" + x + y
