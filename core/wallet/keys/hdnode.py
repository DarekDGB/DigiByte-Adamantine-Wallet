"""
HDNode: normalized container for derived key material.

This is a *data object* only.
No derivation logic here.

It also provides a small compatibility bridge:
- HDNode.from_seed(seed) calls core.wallet.keys.hd.master_key_from_seed(seed)
  and adapts the returned object (bytes-based or *_hex-based) into this HDNode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.wallet.address import hash160
from core.wallet.keys.secp256k1 import pubkey_from_privkey


@dataclass(frozen=True)
class HDNode:
    # BIP32 material
    chain_code: bytes  # 32 bytes
    private_key: Optional[bytes]  # 32 bytes or None (watch-only later)

    # Metadata
    depth: int = 0  # 0..255
    child_num: int = 0  # 0..2^32-1
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

    @staticmethod
    def _hex_to_bytes(value: str, *, expected_len: Optional[int] = None) -> bytes:
        b = bytes.fromhex(value)
        if expected_len is not None and len(b) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
        return b

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDNode":
        """
        Convenience constructor.

        Keeps HDNode ergonomic while keeping derivation logic in core.wallet.keys.hd.
        Adapts different HDNode representations (bytes or *_hex fields) into this class.
        """
        # Lazy import avoids circular dependencies and keeps this module "data-first".
        from core.wallet.keys.hd import master_key_from_seed

        node = master_key_from_seed(seed)

        # Already our HDNode
        if isinstance(node, cls):
            return node

        # Adapt from an alternate HDNode representation used in core.wallet.keys.hd
        # Common shape seen in CI/errors:
        #   chain_code_hex, private_key_hex, parent_fingerprint_hex, depth, child_number
        if hasattr(node, "chain_code_hex"):
            chain_code = cls._hex_to_bytes(getattr(node, "chain_code_hex"), expected_len=32)

            pk_hex = getattr(node, "private_key_hex", None)
            private_key = None if pk_hex is None else cls._hex_to_bytes(pk_hex, expected_len=32)

            pf_hex = getattr(node, "parent_fingerprint_hex", None)
            parent_fingerprint = (
                b"\x00\x00\x00\x00"
                if pf_hex is None
                else cls._hex_to_bytes(pf_hex, expected_len=4)
            )

            depth = int(getattr(node, "depth", 0))
            child_num = int(getattr(node, "child_number", getattr(node, "child_num", 0)))

            path = getattr(node, "path", "m")
            return cls(
                chain_code=chain_code,
                private_key=private_key,
                depth=depth,
                child_num=child_num,
                parent_fingerprint=parent_fingerprint,
                path=path,
            )

        # Adapt from a generic object with bytes fields (chain_code/private_key)
        if hasattr(node, "chain_code") and hasattr(node, "private_key"):
            chain_code = getattr(node, "chain_code")
            private_key = getattr(node, "private_key")
            if not isinstance(chain_code, (bytes, bytearray)):
                raise TypeError("Unexpected chain_code type")
            if private_key is not None and not isinstance(private_key, (bytes, bytearray)):
                raise TypeError("Unexpected private_key type")

            depth = int(getattr(node, "depth", 0))
            child_num = int(getattr(node, "child_num", getattr(node, "child_number", 0)))
            parent_fingerprint = getattr(node, "parent_fingerprint", b"\x00\x00\x00\x00")
            if not isinstance(parent_fingerprint, (bytes, bytearray)):
                raise TypeError("Unexpected parent_fingerprint type")

            path = getattr(node, "path", "m")
            return cls(
                chain_code=bytes(chain_code),
                private_key=None if private_key is None else bytes(private_key),
                depth=depth,
                child_num=child_num,
                parent_fingerprint=bytes(parent_fingerprint),
                path=path,
            )

        raise TypeError("master_key_from_seed() returned an unsupported node type")

    def pubkey(self, compressed: bool = True) -> bytes:
        if self.private_key is None:
            raise ValueError("No private key on this node")
        return pubkey_from_privkey(self.private_key, compressed=compressed)

    def fingerprint(self) -> bytes:
        """
        BIP32 fingerprint = first 4 bytes of HASH160(compressed pubkey)
        """
        return hash160(self.pubkey(compressed=True))[:4]
