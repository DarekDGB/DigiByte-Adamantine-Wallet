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


def address_from_node(node) -> str:
    """
    Convert an HDNode (must contain a private key) into a DigiByte P2PKH address.
    """
    priv = getattr(node, "private_key", None)
    if priv is None:
        raise BridgeError("HDNode has no private key")

    pubkey = pubkey_from_privkey(priv, compressed=True)
    return p2pkh_from_pubkey(pubkey)
