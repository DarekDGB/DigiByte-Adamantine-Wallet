import pytest

from core.wallet.keys.hd import DerivationPath
from core.wallet.bridge import BridgeError, address_from_node


def test_bridge_address_from_node_starts_with_D():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    path = DerivationPath.from_string("m/44'/20'/0'/0/0")

    node = path.derive_from_seed(seed)
    addr = address_from_node(node)

    assert addr.startswith("D")
    assert 26 <= len(addr) <= 36


def test_bridge_requires_private_key():
    class Dummy:
        private_key = None

    with pytest.raises(BridgeError):
        address_from_node(Dummy())
