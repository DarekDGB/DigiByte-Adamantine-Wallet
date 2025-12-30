from core.wallet.keys.secp256k1 import ecdsa_sign, ecdsa_verify, pubkey_from_privkey


def test_ecdsa_sign_then_verify() -> None:
    priv = bytes.fromhex("11" * 32)
    msg32 = bytes.fromhex("22" * 32)

    pub = pubkey_from_privkey(priv, compressed=True)
    sig = ecdsa_sign(msg32, priv)

    assert ecdsa_verify(msg32, sig, pub) is True


def test_ecdsa_verify_fails_on_different_msg() -> None:
    priv = bytes.fromhex("11" * 32)
    msg32 = bytes.fromhex("22" * 32)
    msg32b = bytes.fromhex("33" * 32)

    pub = pubkey_from_privkey(priv, compressed=True)
    sig = ecdsa_sign(msg32, priv)

    assert ecdsa_verify(msg32b, sig, pub) is False
