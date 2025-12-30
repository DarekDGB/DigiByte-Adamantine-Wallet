"""
HDNode: normalized container for derived key material.

This is a *data object* only.
No derivation logic here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.wallet.address import hash160
from core.wallet.keys.secp256k1 import pubkey_from_privkey


@dataclass(frozen=True)
class HDNode:
    # BIP32 material
    chain_code: bytes                 # 32 bytes
    private_key: Optional[bytes]      # 32 bytes or None (watch-only later)

    # Metadata
    depth: int = 0                   # 0..255
    child_num: int = 0               # 0..2^32-1
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"  # 4 bytes

    # Optional path string for debugging/docs (not used in crypto)
    path: str = "m"

    def __post_init__(self) -> None:
        if len(self.chain_code) != 32:
            raise ValueError("chain_code must be 32 bytes")
        if self.private_key is not None and len(self.private_key) != 32:
            raise ValueError("private_key must be 32 bytes or None")
        if not (0 <= self.depth <= 255):
            raise ValueError("depth must be 0..255")
        if not (0 <= self.child_num <= 0xFFFFFFFF):
            raise ValueError("child_num must be 0..2^32-1")
        if len(self.parent_fingerprint) != 4:
            raise ValueError("parent_fingerprint must be 4 bytes")

    def pubkey(self, compressed: bool = True) -> bytes:
        if self.private_key is None:
            raise ValueError("No private key on this node")
        return pubkey_from_privkey(self.private_key, compressed=compressed)

    def fingerprint(self) -> bytes:
        """
        BIP32 fingerprint = first 4 bytes of HASH160(compressed pubkey)
        """
        return hash160(self.pubkey(compressed=True))[:4]
