"""
HD Wallet (BIP32/BIP44) — CKDpriv hardened + non-hardened + BIP44 helpers

Now implements:
- BIP32 master key derivation from seed
- CKDpriv hardened (i >= 2^31)
- CKDpriv non-hardened (i < 2^31)  <-- requires parent pubkey
- Parent fingerprint (hash160(pubkey)[:4])
- BIP44 helpers to derive:
  m/44'/coin'/account' (hardened)
  then /change/index (non-hardened)

TODO (next phases):
- xprv/xpub serialization (base58check)
- address encoding (P2PKH/P2WPKH etc) + DigiByte formats
"""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from ..errors import WalletError
from .secp256k1 import pubkey_from_privkey, N as SECP256K1_N


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


def _parse256(b: bytes) -> int:
    if len(b) != 32:
        raise BIP32Error("parse256 expects 32 bytes.")
    return int.from_bytes(b, "big")


def hash160(data: bytes) -> bytes:
    """
    HASH160 = RIPEMD160(SHA256(data))
    """
    sha = hashlib.sha256(data).digest()
    try:
        rip = hashlib.new("ripemd160")
    except ValueError as e:
        raise BIP32Error("ripemd160 not available in hashlib on this platform.") from e
    rip.update(sha)
    return rip.digest()


def fingerprint_from_pubkey(pubkey_bytes: bytes) -> bytes:
    return hash160(pubkey_bytes)[:4]


def master_key_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    if not isinstance(seed, (bytes, bytearray)):
        raise BIP32Error("Seed must be bytes.")
    if len(seed) < 16 or len(seed) > 64:
        raise BIP32Error("Seed length looks invalid (expected 16..64 bytes).")

    I = _hmac_sha512(b"Bitcoin seed", bytes(seed))
    return I[:32], I[32:]


def ckdpriv_hardened(parent_privkey_32: bytes, parent_chaincode_32: bytes, child_number: int) -> Tuple[bytes, bytes]:
    if len(parent_privkey_32) != 32:
        raise BIP32Error("Parent privkey must be 32 bytes.")
    if len(parent_chaincode_32) != 32:
        raise BIP32Error("Parent chain code must be 32 bytes.")
    if child_number < HARDENED_OFFSET:
        raise BIP32Error("Only hardened child numbers supported here (i >= 2^31).")

    kpar = _parse256(parent_privkey_32)
    if kpar <= 0 or kpar >= SECP256K1_N:
        raise BIP32Error("Invalid parent private key scalar.")

    data = b"\x00" + parent_privkey_32 + _ser32(child_number)
    I = _hmac_sha512(parent_chaincode_32, data)
    IL, IR = I[:32], I[32:]

    il_int = _parse256(IL)
    if il_int >= SECP256K1_N:
        raise BIP32Error("Derived IL invalid (>= n).")

    ki = (il_int + kpar) % SECP256K1_N
    if ki == 0:
        raise BIP32Error("Derived child private key is zero (invalid).")

    return _ser256(ki), IR


def ckdpriv_nonhardened(parent_privkey_32: bytes, parent_chaincode_32: bytes, child_number: int) -> Tuple[bytes, bytes]:
    """
    Non-hardened CKDpriv (i < 2^31) requires parent public key:
      data = serP(Kpar) || ser32(i)
    """
    if child_number >= HARDENED_OFFSET:
        raise BIP32Error("Non-hardened child_number must be < 2^31.")
    if len(parent_privkey_32) != 32 or len(parent_chaincode_32) != 32:
        raise BIP32Error("Parent privkey/chaincode must be 32 bytes each.")

    kpar = _parse256(parent_privkey_32)
    if kpar <= 0 or kpar >= SECP256K1_N:
        raise BIP32Error("Invalid parent private key scalar.")

    parent_pub = pubkey_from_privkey(parent_privkey_32, compressed=True)
    data = parent_pub + _ser32(child_number)

    I = _hmac_sha512(parent_chaincode_32, data)
    IL, IR = I[:32], I[32:]

    il_int = _parse256(IL)
    if il_int >= SECP256K1_N:
        raise BIP32Error("Derived IL invalid (>= n).")

    ki = (il_int + kpar) % SECP256K1_N
    if ki == 0:
        raise BIP32Error("Derived child private key is zero (invalid).")

    return _ser256(ki), IR


@dataclass(frozen=True)
class HDNode:
    depth: int
    child_number: int
    private_key_hex: str
    chain_code_hex: str
    parent_fingerprint_hex: str = "00000000"  # root has 00000000

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDNode":
        priv, cc = master_key_from_seed(seed)
        return cls(
            depth=0,
            child_number=0,
            private_key_hex=priv.hex(),
            chain_code_hex=cc.hex(),
            parent_fingerprint_hex="00000000",
        )

    def _priv_bytes(self) -> bytes:
        return bytes.fromhex(self.private_key_hex)

    def _cc_bytes(self) -> bytes:
        return bytes.fromhex(self.chain_code_hex)

    def pubkey_compressed(self) -> bytes:
        return pubkey_from_privkey(self._priv_bytes(), compressed=True)

    def fingerprint(self) -> bytes:
        return fingerprint_from_pubkey(self.pubkey_compressed())

    def derive_hardened(self, index: int) -> "HDNode":
        if index < 0 or index > 0x7FFFFFFF:
            raise BIP32Error("Hardened index must be 0..2^31-1.")
        child_number = index + HARDENED_OFFSET

        child_priv, child_cc = ckdpriv_hardened(self._priv_bytes(), self._cc_bytes(), child_number)
        return HDNode(
            depth=self.depth + 1,
            child_number=child_number,
            private_key_hex=child_priv.hex(),
            chain_code_hex=child_cc.hex(),
            parent_fingerprint_hex=self.fingerprint().hex(),
        )

    def derive_nonhardened(self, index: int) -> "HDNode":
        if index < 0 or index > 0x7FFFFFFF:
            raise BIP32Error("Non-hardened index must be 0..2^31-1.")
        child_number = index  # non-hardened

        child_priv, child_cc = ckdpriv_nonhardened(self._priv_bytes(), self._cc_bytes(), child_number)
        return HDNode(
            depth=self.depth + 1,
            child_number=child_number,
            private_key_hex=child_priv.hex(),
            chain_code_hex=child_cc.hex(),
            parent_fingerprint_hex=self.fingerprint().hex(),
        )

    def derive_path(self, path: DerivationPath) -> "HDNode":
        node: HDNode = self
        for seg in path.segments:
            if seg.hardened:
                node = node.derive_hardened(seg.index)
            else:
                node = node.derive_nonhardened(seg.index)
        return node


# ----------------------------
# BIP44 helpers
# ----------------------------

def derive_bip44_account(root: HDNode, coin_type: int, account: int = 0) -> HDNode:
    # m/44'/coin_type'/account'
    if coin_type < 0 or coin_type > 0x7FFFFFFF:
        raise BIP32Error("coin_type must be 0..2^31-1.")
    if account < 0 or account > 0x7FFFFFFF:
        raise BIP32Error("account must be 0..2^31-1.")
    return root.derive_hardened(44).derive_hardened(coin_type).derive_hardened(account)


def derive_bip44_chain(account_node: HDNode, change: int = 0) -> HDNode:
    # /change (0 external, 1 internal)
    if change not in (0, 1):
        raise BIP32Error("change must be 0 (external) or 1 (internal).")
    return account_node.derive_nonhardened(change)


def derive_bip44_address(account_node: HDNode, change: int, index: int) -> HDNode:
    # /change/index
    if index < 0 or index > 0x7FFFFFFF:
        raise BIP32Error("index must be 0..2^31-1.")
    return derive_bip44_chain(account_node, change).derive_nonhardened(index)
