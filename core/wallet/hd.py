"""
HD Wallet scaffolding (BIP32 / BIP44)

This file is intentionally lightweight (iPhone + CI-safe).
We implement:
- DerivationPath parsing (m/44'/coin'/account'/change/index)
- Strong validation + helpers

TODO (next phases):
- BIP32 private/public key derivation (HMAC-SHA512)
- secp256k1 pubkey generation
- xprv/xpub serialization (base58check)
- DigiByte coin type + network versions
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from ..errors import WalletError, NotImplementedYet


HARDENED_OFFSET = 0x80000000


class HDPathError(WalletError):
    """Invalid HD derivation path."""


@dataclass(frozen=True)
class DerivationIndex:
    index: int
    hardened: bool = False

    def to_uint32(self) -> int:
        if self.index < 0:
            raise HDPathError("Index cannot be negative.")
        if self.index > 0x7FFFFFFF:
            raise HDPathError("Index too large (max 2^31-1).")
        return self.index + (HARDENED_OFFSET if self.hardened else 0)


@dataclass(frozen=True)
class DerivationPath:
    """
    Represents a BIP32 style path, e.g.:
      m/44'/0'/0'/0/0
    """
    segments: Tuple[DerivationIndex, ...]

    @classmethod
    def parse(cls, path: str) -> "DerivationPath":
        if not path:
            raise HDPathError("Path is empty.")

        p = path.strip()
        if p == "m":
            return cls(segments=tuple())

        if not p.startswith("m/"):
            raise HDPathError("Path must start with 'm/' or be exactly 'm'.")

        parts = p[2:].split("/")
        if any(part.strip() == "" for part in parts):
            raise HDPathError("Path contains an empty segment.")

        segs: List[DerivationIndex] = []
        for part in parts:
            hardened = part.endswith("'") or part.endswith("h") or part.endswith("H")
            raw = part[:-1] if hardened else part

            if not raw.isdigit():
                raise HDPathError(f"Invalid path segment: {part}")

            idx = int(raw, 10)
            segs.append(DerivationIndex(index=idx, hardened=hardened))

        return cls(segments=tuple(segs))

    def to_uint32_list(self) -> List[int]:
        return [s.to_uint32() for s in self.segments]


def bip44_path(coin_type: int, account: int = 0, change: int = 0, address_index: int = 0) -> DerivationPath:
    """
    Standard BIP44 path:
      m / 44' / coin_type' / account' / change / address_index
    """
    if change not in (0, 1):
        raise HDPathError("change must be 0 (external) or 1 (internal).")

    return DerivationPath(
        segments=(
            DerivationIndex(44, hardened=True),
            DerivationIndex(coin_type, hardened=True),
            DerivationIndex(account, hardened=True),
            DerivationIndex(change, hardened=False),
            DerivationIndex(address_index, hardened=False),
        )
    )


@dataclass(frozen=True)
class HDNode:
    """
    Minimal HD node container.

    TODO:
    - Store private key bytes securely
    - Compute public key
    - Derive child keys per BIP32
    """
    depth: int
    child_number: int
    chain_code_hex: str

    def derive(self, path: DerivationPath) -> "HDNode":
        raise NotImplementedYet("TODO: implement BIP32 derive().")
