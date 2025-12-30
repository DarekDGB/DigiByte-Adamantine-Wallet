import pytest

from core.wallet.encoding.base58check import (
    Base58Error,
    base58check_decode,
    base58check_encode,
)


def test_base58check_roundtrip():
    v = 0x1E
    payload = b"\x00" * 20
    s = base58check_encode(v, payload)
    dec = base58check_decode(s)
    assert dec.version == v
    assert dec.payload == payload


def test_base58check_bad_checksum():
    v = 0x1E
    payload = b"\x11" * 20
    s = base58check_encode(v, payload)
    # flip last char (almost certainly breaks checksum)
    bad = s[:-1] + ("1" if s[-1] != "1" else "2")
    with pytest.raises(Base58Error):
        base58check_decode(bad)
