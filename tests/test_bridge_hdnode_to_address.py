import pytest

from core.wallet.bridge import BridgeError, address_from_node


class DummyNode:
    def __init__(self, private_key: bytes | None):
        self.private_key = private_key


def test_bridge_address_from_node_known_vector_privkey_1():
    # Private key = 1 (32 bytes big-endian)
    node = DummyNode(b"\x00" * 31 + b"\x01")

    addr = address_from_node(node)

    # Deterministic DigiByte P2PKH result for privkey=1 (compressed pubkey)
    assert addr == "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"


def test_bridge_requires_private_key():
    node = DummyNode(None)
    with pytest.raises(BridgeError):
        address_from_node(node)
