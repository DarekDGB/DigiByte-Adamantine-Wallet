"""
HD Wallet (BIP32/BIP44) — hardened-only CKDpriv

Implements:
- DerivationPath parsing (m/44'/coin'/account'/change/index)
- BIP32 master key derivation from seed
- BIP32 hardened child private derivation (CKDpriv for i >= 2^31)

Still intentionally lightweight:
- No public key math yet (no secp256k1 point multiplication)
- No xprv/xpub serialization yet

TODO (next phases):
- Non-hardened CKD (requires parent public key)
- Pubkey generation (secp256k1)
- xprv/xpub serialization (base58check)
- Fingerprints (requires pubkey hash160)
- DigiByte version bytes + address formats
"""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from ..errors import WalletError


HARDENED_OFFSET = 0x80000000

# secp256k1 curve order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


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


def _ser32(i: int) -> bytes:
    if i < 0 or i > 0xFFFFFFFF:
        raise BIP32Error("Child number out of range (0..2^32-1).")
    return i.to_bytes(4, "big")


def _ser256(i: int) -> bytes:
    if i < 0 or i >= (1 << 256):
        raise BIP32Error("Integer out of range for ser256.")
    return i.to_bytes(32, "big")


def master_key_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """
    BIP32 master key derivation:
      I = HMAC-SHA512(key="Bitcoin seed", data=seed)
      master_privkey = IL (32 bytes)
      master_chaincode = IR (32 bytes)
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise BIP32Error("Seed must be bytes.")
    if len(seed) < 16 or len(seed) > 64:
        raise BIP32Error("Seed length looks invalid (expected 16..64 bytes).")

    I = _hmac_sha512(b"Bitcoin seed", bytes(seed))
    IL, IR = I[:32], I[32:]
    return IL, IR


def ckdpriv_hardened(parent_privkey_32: bytes, parent_chaincode_32: bytes, child_number: int) -> Tuple[bytes, bytes]:
    """
    BIP32 hardened private child derivation (CKDpriv), for i >= 2^31:

      data = 0x00 || ser256(kpar) || ser32(i)
      I = HMAC-SHA512(key=cpar, data=data)
      IL, IR = I[0:32], I[32:64]
      ki = (parse256(IL) + kpar) mod n
      ci = IR

    Returns: (child_privkey_32, child_chaincode_32)
    """
    if len(parent_privkey_32) != 32:
        raise BIP32Error("Parent privkey must be 32 bytes.")
    if len(parent_chaincode_32) != 32:
        raise BIP32Error("Parent chain code must be 32 bytes.")
    if child_number < HARDENED_OFFSET:
        raise BIP32Error("This function only supports hardened child numbers (i >= 2^31).")

    kpar = int.from_bytes(parent_privkey_32, "big")
    if kpar <= 0 or kpar >= SECP256K1_N:
        raise BIP32Error("Invalid parent private key scalar.")

    data = b"\x00" + parent_privkey_32 + _ser32(child_number)
    I = _hmac_sha512(parent_chaincode_32, data)
    IL, IR = I[:32], I[32:]

    il_int = int.from_bytes(IL, "big")
    if il_int >= SECP256K1_N:
        # Spec says: invalid, increment i and retry. We keep it strict for now.
        raise BIP32Error("Derived IL is invalid (>= n).")

    ki = (il_int + kpar) % SECP256K1_N
    if ki == 0:
        raise BIP32Error("Derived child private key is zero (invalid).")

    return _ser256(ki), IR


@dataclass(frozen=True)
class HDNode:
    """
    Minimal HD private node container (hardened derivation only).
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

    def _priv_bytes(self) -> bytes:
        return bytes.fromhex(self.private_key_hex)

    def _cc_bytes(self) -> bytes:
        return bytes.fromhex(self.chain_code_hex)

    def derive_hardened(self, index: int) -> "HDNode":
        """
        Derive hardened child at index (without adding HARDENED_OFFSET yourself).
        Example: node.derive_hardened(0) == m/0'
        """
        if index < 0 or index > 0x7FFFFFFF:
            raise BIP32Error("Hardened index must be 0..2^31-1.")
        child_number = index + HARDENED_OFFSET

        child_priv, child_cc = ckdpriv_hardened(self._priv_bytes(), self._cc_bytes(), child_number)
        return HDNode(
            depth=self.depth + 1,
            child_number=child_number,
            private_key_hex=child_priv.hex(),
            chain_code_hex=child_cc.hex(),
        )

    def derive_path_hardened_only(self, path: DerivationPath) -> "HDNode":
        """
        Derive a path, but ONLY if every segment is hardened.
        """
        node: HDNode = self
        for seg in path.segments:
            if not seg.hardened:
                raise BIP32Error("Non-hardened derivation not supported yet.")
            node = node.derive_hardened(seg.index)
        return node
