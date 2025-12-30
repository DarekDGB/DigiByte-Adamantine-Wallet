import pytest

from core.wallet.address import AddressError, p2pkh_from_pubkey_hash


def test_dgb_p2pkh_known_vector_all_zero_hash():
    # version=0x1E + 20x00 + checksum => known Base58Check string
    assert p2pkh_from_pubkey_hash(b"\x00" * 20) == "D596YFweJQuHY1BbjazZYmAbt8jJPbKehC"


def test_dgb_p2pkh_hash_length_validation():
    with pytest.raises(AddressError):
        p2pkh_from_pubkey_hash(b"\x00" * 19)
    with pytest.raises(AddressError):
        p2pkh_from_pubkey_hash(b"\x00" * 21)
