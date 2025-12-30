from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.wallet.address import hash160


@dataclass(frozen=True)
class PublicHDNode:
    """
    Watch-only (public) BIP32 node:
    - has chain_code + public_key
    - has NO private key
    """
    chain_code: bytes       # 32 bytes
    public_key: bytes       # 33 bytes compressed
    depth: int = 0
    child_num: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    path: str = "m"

    def __post_init__(self) -> None:
        if len(self.chain_code) != 32:
            raise ValueError("chain_code must be 32 bytes")
        if len(self.public_key) != 33:
            raise ValueError("public_key must be 33 bytes (compressed)")
        if not (0 <= self.depth <= 255):
            raise ValueError("depth must be 0..255")
        if not (0 <= self.child_num <= 0xFFFFFFFF):
            raise ValueError("child_num must be 0..2^32-1")
        if len(self.parent_fingerprint) != 4:
            raise ValueError("parent_fingerprint must be 4 bytes")

    def pubkey(self) -> bytes:
        return self.public_key

    def fingerprint(self) -> bytes:
        return hash160(self.public_key)[:4]
