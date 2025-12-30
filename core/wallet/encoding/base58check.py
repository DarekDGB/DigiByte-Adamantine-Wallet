"""
Base58 + Base58Check (double-SHA256 checksum)

Used for legacy addresses (P2PKH/P2SH) and later xpub/xprv serialization.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


class Base58Error(ValueError):
    """Raised when Base58/Base58Check decoding fails."""


def b58encode(data: bytes) -> str:
    if not data:
        return ""

    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _ALPHABET[rem] + out

    # Preserve leading 0x00 bytes as '1'
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break

    return ("1" * pad) + (out or "")


def b58decode(text: str) -> bytes:
    if text == "":
        return b""

    n = 0
    for ch in text:
        if ch not in _INDEX:
            raise Base58Error(f"Invalid base58 character: {ch!r}")
        n = n * 58 + _INDEX[ch]

    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""

    # Restore leading zeros
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break

    return (b"\x00" * pad) + raw


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def base58check_encode(version: int, payload: bytes) -> str:
    if not (0 <= version <= 255):
        raise ValueError("version must be 0..255")

    data = bytes([version]) + payload
    checksum = _hash256(data)[:4]
    return b58encode(data + checksum)


@dataclass(frozen=True)
class Base58CheckDecoded:
    version: int
    payload: bytes


def base58check_decode(text: str) -> Base58CheckDecoded:
    raw = b58decode(text)
    if len(raw) < 5:
        raise Base58Error("Base58Check string too short")

    data, checksum = raw[:-4], raw[-4:]
    expected = _hash256(data)[:4]
    if checksum != expected:
        raise Base58Error("Invalid Base58Check checksum")

    return Base58CheckDecoded(version=data[0], payload=data[1:])
