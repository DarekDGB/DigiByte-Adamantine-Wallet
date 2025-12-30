"""
Bridge layer: HDNode -> DigiByte address.

This module intentionally contains *no crypto primitives*.
It only connects existing components:
- HD derivation (BIP32/BIP44)
- secp256k1 pubkey (from private key)
- address encoding (Base58Check -> DigiByte P2PKH)
"""

from __future__ import annotations

from core.wallet.address import p2pkh_from_pubkey
from core.wallet.keys.secp256k1 import pubkey_from_privkey


class BridgeError(ValueError):
    """Raised when an HD node cannot be converted into an address."""


def _extract_privkey_bytes(node) -> bytes:
    """
    Accept both node styles:
    - node.private_key: bytes (new HDNode data object)
    - node.private_key_hex: str (current BIP32 HDNode)
    """
    priv = getattr(node, "private_key", None)
    if isinstance(priv, (bytes, bytearray)):
        if len(priv) != 32:
            raise BridgeError("private_key must be 32 bytes")
        return bytes(priv)

    priv_hex = getattr(node, "private_key_hex", None)
    if isinstance(priv_hex, str) and priv_hex:
        try:
            b = bytes.fromhex(priv_hex)
        except ValueError as e:
            raise BridgeError("private_key_hex is not valid hex") from e
        if len(b) != 32:
            raise BridgeError("private_key_hex must decode to 32 bytes")
        return b

    raise BridgeError("HDNode has no private key")


def address_from_node(node) -> str:
    """
    Convert an HDNode (must contain a private key) into a DigiByte P2PKH address.
    """
    priv_bytes = _extract_privkey_bytes(node)
    pubkey = pubkey_from_privkey(priv_bytes, compressed=True)
    return p2pkh_from_pubkey(pubkey)
