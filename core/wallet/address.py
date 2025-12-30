"""
Legacy DigiByte address utilities (P2PKH).

Phase 4 scope:
- pubkey -> hash160
- hash160 -> Base58Check address (P2PKH)

No P2SH / Bech32 / scripts yet.
"""

from __future__ import annotations

import hashlib

from core.wallet.encoding.base58check import base58check_encode


class AddressError(ValueError):
    """Raised when an address cannot be created/validated."""


# DigiByte legacy P2PKH version byte (D... addresses)
DGB_P2PKH_VERSION = 0x1E  # 30


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160")
    ripe.update(sha)
    return ripe.digest()


def p2pkh_from_pubkey_hash(pubkey_hash20: bytes, version: int = DGB_P2PKH_VERSION) -> str:
    if len(pubkey_hash20) != 20:
        raise AddressError("pubkey_hash20 must be exactly 20 bytes")
    return base58check_encode(version, pubkey_hash20)


def p2pkh_from_pubkey(pubkey_bytes: bytes, version: int = DGB_P2PKH_VERSION) -> str:
    return p2pkh_from_pubkey_hash(hash160(pubkey_bytes), version=version)
