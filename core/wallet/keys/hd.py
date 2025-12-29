"""
HD Wallet scaffolding (BIP32 / BIP44) + BIP32 master key derivation

Implements:
- DerivationPath parsing (m/44'/coin'/account'/change/index)
- BIP32 master key derivation from seed (HMAC-SHA512 with key "Bitcoin seed")

TODO (next phases):
- Child key derivation (CKDpriv/CKDpub)
- secp256k1 pubkey generation
- xprv/xpub serialization (base58check)
- DigiByte-specific version bytes + address formats
"""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from ..errors import WalletError, NotImplementedYet


HARDENED_OFFSET = 0x80000000


class HDPathError(WalletError):
    """Invalid HD derivation path."""


class BIP32Error(WalletError):
    """BIP32 derivation error."""


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


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def master_key_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """
    BIP32 master key derivation:
      I = HMAC-SHA512(key="Bitcoin seed", data=seed)
      master_privkey = IL (32 bytes)
      master_chaincode = IR (32 bytes)

    Returns: (master_private_key_32, master_chain_code_32)

    NOTE:
    - We do NOT validate curve order here yet (requires secp256k1 constants).
      That validation is added when we introduce real child derivation.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise BIP32Error("Seed must be bytes.")
    if len(seed) < 16 or len(seed) > 64:
        # BIP39 seed is 64 bytes, but we accept common ranges to be safe.
        raise BIP32Error("Seed length looks invalid (expected 16..64 bytes).")

    I = _hmac_sha512(b"Bitcoin seed", bytes(seed))
    IL, IR = I[:32], I[32:]
    if len(IL) != 32 or len(IR) != 32:
        raise BIP32Error("Unexpected HMAC output length.")
    return IL, IR


@dataclass(frozen=True)
class HDNode:
    """
    Minimal HD node container.

    For now we keep only what we can safely compute without secp256k1 math:
    - private_key (hex)
    - chain_code (hex)
    """
    depth: int
    child_number: int
    private_key_hex: str
    chain_code_hex: str

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDNode":
        priv, cc = master_key_from_seed(seed)
        return cls(
            depth=0,
            child_number=0,
            private_key_hex=priv.hex(),
            chain_code_hex=cc.hex(),
        )

    def derive(self, path: DerivationPath) -> "HDNode":
        raise NotImplementedYet("TODO: implement BIP32 child derivation (CKDpriv).")
