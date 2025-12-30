import pytest

from core.wallet.keys.hdnode import HDNode


def test_hdnode_validates_lengths():
    with pytest.raises(ValueError):
        HDNode(chain_code=b"\x00" * 31, private_key=b"\x00" * 32)

    with pytest.raises(ValueError):
        HDNode(chain_code=b"\x00" * 32, private_key=b"\x00" * 31)

    # watch-only allowed (private_key None)
    n = HDNode(chain_code=b"\x11" * 32, private_key=None)
    assert n.private_key is None


def test_hdnode_pubkey_requires_privkey():
    n = HDNode(chain_code=b"\x11" * 32, private_key=None)
    with pytest.raises(ValueError):
        n.pubkey()


def test_hdnode_fingerprint_is_4_bytes():
    # privkey=1
    n = HDNode(chain_code=b"\x22" * 32, private_key=b"\x00" * 31 + b"\x01")
    fp = n.fingerprint()
    assert isinstance(fp, (bytes, bytearray))
    assert len(fp) == 4
