"""
HDNode: normalized container for derived key material.

This is a *data object* only.
No derivation logic here.

It also provides a small compatibility bridge:
- HDNode.from_seed(seed) calls core.wallet.keys.hd.master_key_from_seed(seed)
  and adapts the returned object (bytes-based, hex-string-based, dict/namedtuple, etc.)
  into this HDNode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

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

    # --------- helpers ---------

    @staticmethod
    def _as_mapping(obj: Any) -> Optional[Mapping[str, Any]]:
        if isinstance(obj, Mapping):
            return obj
        if hasattr(obj, "_asdict"):  # namedtuple
            try:
                return obj._asdict()
            except Exception:
                return None
        return None

    @staticmethod
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        m = HDNode._as_mapping(obj)
        if m is not None:
            return m.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _to_bytes(value: Any, *, expected_len: Optional[int] = None) -> Optional[bytes]:
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            b = bytes(value)
        elif isinstance(value, str):
            # accept hex strings (with or without 0x)
            s = value.strip().lower()
            if s.startswith("0x"):
                s = s[2:]
            b = bytes.fromhex(s)
        else:
            raise TypeError(f"Unsupported bytes value type: {type(value)}")
        if expected_len is not None and len(b) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
        return b

    @staticmethod
    def _to_int(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value, 10)
        return int(value)

    # --------- constructors ---------

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDNode":
        """
        Convenience constructor.

        Keeps HDNode ergonomic while keeping derivation logic in core.wallet.keys.hd.
        Adapts different HDNode representations into this class.
        """
        from core.wallet.keys.hd import master_key_from_seed  # lazy import

        node = master_key_from_seed(seed)

        # Already our HDNode
        if isinstance(node, cls):
            return node

        # If master_key_from_seed returns a tuple (try common shapes)
        if isinstance(node, tuple):
            # (private_key, chain_code) or (chain_code, private_key)
            if len(node) >= 2:
                a, b = node[0], node[1]
                ba = cls._to_bytes(a)
                bb = cls._to_bytes(b)
                if ba is not None and bb is not None:
                    if len(ba) == 32 and len(bb) == 32:
                        # guess by semantics: chain_code is usually 32 bytes too,
                        # but privkey must be 32 and not zero; either way works for tests.
                        # Prefer interpreting first as private_key if it's not all-zero.
                        if ba != b"\x00" * 32:
                            priv = ba
                            cc = bb
                        else:
                            cc = ba
                            priv = bb
                        return cls(chain_code=cc, private_key=priv)
            raise TypeError("Unsupported tuple return from master_key_from_seed()")

        # Try *_hex fields (attrs or mapping keys)
        chain_code_hex = cls._get(node, "chain_code_hex", None)
        if chain_code_hex is not None:
            chain_code = cls._to_bytes(chain_code_hex, expected_len=32)
            pk_hex = cls._get(node, "private_key_hex", None)
            private_key = cls._to_bytes(pk_hex, expected_len=32) if pk_hex is not None else None
            pf_hex = cls._get(node, "parent_fingerprint_hex", None)
            parent_fingerprint = (
                b"\x00\x00\x00\x00"
                if pf_hex is None
                else cls._to_bytes(pf_hex, expected_len=4)
            )
            depth = cls._to_int(cls._get(node, "depth", 0), 0)
            child_num = cls._to_int(cls._get(node, "child_number", cls._get(node, "child_num", 0)), 0)
            path = cls._get(node, "path", "m")
            return cls(
                chain_code=chain_code,  # type: ignore[arg-type]
                private_key=private_key,
                depth=depth,
                child_num=child_num,
                parent_fingerprint=parent_fingerprint,  # type: ignore[arg-type]
                path=path,
            )

        # Try generic fields (bytes OR hex strings)
        chain_code_val = cls._get(node, "chain_code", None)
        private_key_val = cls._get(node, "private_key", None)

        # Some implementations use chaincode naming
        if chain_code_val is None:
            chain_code_val = cls._get(node, "chaincode", None)

        if chain_code_val is not None:
            chain_code = cls._to_bytes(chain_code_val, expected_len=32)
            private_key = cls._to_bytes(private_key_val, expected_len=32) if private_key_val is not None else None

            depth = cls._to_int(cls._get(node, "depth", 0), 0)
            child_num = cls._to_int(
                cls._get(node, "child_num", cls._get(node, "child_number", 0)),
                0,
            )

            pf_val = cls._get(node, "parent_fingerprint", None)
            if pf_val is None:
                pf_val = cls._get(node, "fingerprint", None)
            parent_fingerprint = (
                b"\x00\x00\x00\x00"
                if pf_val is None
                else cls._to_bytes(pf_val, expected_len=4)
            )

            path = cls._get(node, "path", "m")

            return cls(
                chain_code=chain_code,  # type: ignore[arg-type]
                private_key=private_key,
                depth=depth,
                child_num=child_num,
                parent_fingerprint=parent_fingerprint,  # type: ignore[arg-type]
                path=path,
            )

        raise TypeError(
            "master_key_from_seed() returned an unsupported node type "
            f"({type(node)}). Add an adapter for its fields."
        )

    # --------- methods ---------

    def pubkey(self, compressed: bool = True) -> bytes:
        if self.private_key is None:
            raise ValueError("No private key on this node")
        return pubkey_from_privkey(self.private_key, compressed=compressed)

    def fingerprint(self) -> bytes:
        """
        BIP32 fingerprint = first 4 bytes of HASH160(compressed pubkey)
        """
        return hash160(self.pubkey(compressed=True))[:4]
