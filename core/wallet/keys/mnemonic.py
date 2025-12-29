"""
BIP39 Mnemonic (Option B: spec-clean, strict)

Implements:
- NFKD normalization (per BIP39)
- Strict wordlist membership + checksum validation
- Mnemonic generation from entropy
- Seed derivation via PBKDF2-HMAC-SHA512 (2048 rounds)

Requires:
- core/wallet/keys/wordlist_en.txt (2048 words, one per line)
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from ..errors import WalletError


class MnemonicError(WalletError):
    """BIP39 mnemonic error."""


@dataclass(frozen=True)
class Mnemonic:
    words: List[str]

    @property
    def phrase(self) -> str:
        return " ".join(self.words)


def _nfkd(text: str) -> str:
    # BIP39 requires NFKD normalization for both mnemonic and passphrase.
    return unicodedata.normalize("NFKD", text)


def _normalize_phrase(phrase: str) -> str:
    # Lowercase + trim + collapse whitespace + NFKD.
    # (English list is lowercase; strictness helps avoid user mistakes.)
    p = " ".join((phrase or "").strip().split())
    p = p.lower()
    return _nfkd(p)


def _wordlist_path() -> Path:
    return Path(__file__).resolve().parent / "wordlist_en.txt"


def load_wordlist() -> List[str]:
    path = _wordlist_path()
    if not path.exists():
        raise MnemonicError("Missing wordlist_en.txt (BIP39 English wordlist).")

    words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise MnemonicError(f"Invalid wordlist length: {len(words)} (expected 2048).")

    # Ensure no duplicates (wordlist must be unique).
    if len(set(words)) != 2048:
        raise MnemonicError("Wordlist contains duplicates.")

    return words


def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def _bits_to_int(bits: str) -> int:
    return int(bits, 2)


def _checksum_bits(entropy: bytes) -> str:
    # CS = ENT / 32
    ent_bits_len = len(entropy) * 8
    cs_len = ent_bits_len // 32
    digest = hashlib.sha256(entropy).digest()
    digest_bits = _bytes_to_bits(digest)
    return digest_bits[:cs_len]


def _validate_entropy_length(entropy: bytes) -> None:
    # Allowed ENT sizes: 128, 160, 192, 224, 256 bits
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise MnemonicError("Entropy must be 16/20/24/28/32 bytes (128..256 bits).")


def from_phrase(phrase: str) -> Mnemonic:
    # Accept user input, normalize it, and validate checksum.
    normalized = _normalize_phrase(phrase)
    words = [w for w in normalized.split(" ") if w]

    if len(words) not in (12, 15, 18, 21, 24):
        raise MnemonicError("Mnemonic must be 12/15/18/21/24 words.")

    # Validate words + checksum
    validate_words(words)
    validate_checksum(words)

    return Mnemonic(words=words)


def validate_words(words: Sequence[str]) -> None:
    wl = load_wordlist()
    wl_set = set(wl)
    for w in words:
        if w not in wl_set:
            raise MnemonicError(f"Invalid mnemonic word: {w}")


def validate_checksum(words: Sequence[str]) -> None:
    """
    Reconstruct entropy+checksum bits from words and validate checksum.
    """
    wl = load_wordlist()
    index = {w: i for i, w in enumerate(wl)}

    # Each word encodes 11 bits
    bits = "".join(f"{index[w]:011b}" for w in words)

    total_bit_len = len(bits)
    # ENT = (words * 11) * 32 / 33
    ent_bit_len = (total_bit_len * 32) // 33
    cs_bit_len = total_bit_len - ent_bit_len

    ent_bits = bits[:ent_bit_len]
    cs_bits = bits[ent_bit_len:]

    if cs_bit_len != ent_bit_len // 32:
        raise MnemonicError("Invalid mnemonic length/checksum sizing.")

    # Convert entropy bits back to bytes
    entropy_int = _bits_to_int(ent_bits)
    entropy_bytes = entropy_int.to_bytes(ent_bit_len // 8, byteorder="big")

    _validate_entropy_length(entropy_bytes)

    expected_cs = _checksum_bits(entropy_bytes)
    if cs_bits != expected_cs:
        raise MnemonicError("Checksum mismatch.")


def generate(strength_bits: int = 128) -> Mnemonic:
    """
    Generate a new mnemonic from random entropy.
    strength_bits must be one of: 128, 160, 192, 224, 256
    """
    if strength_bits not in (128, 160, 192, 224, 256):
        raise MnemonicError("strength_bits must be 128/160/192/224/256.")

    ent_bytes = strength_bits // 8
    entropy = os.urandom(ent_bytes)

    wl = load_wordlist()
    ent_bits = _bytes_to_bits(entropy)
    cs_bits = _checksum_bits(entropy)
    full_bits = ent_bits + cs_bits

    # Split into 11-bit chunks
    words = []
    for i in range(0, len(full_bits), 11):
        chunk = full_bits[i : i + 11]
        idx = _bits_to_int(chunk)
        words.append(wl[idx])

    # Final strict validation
    validate_checksum(words)
    return Mnemonic(words=words)


def seed_from_mnemonic(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    """
    Derive 64-byte seed from mnemonic per BIP39:
    PBKDF2-HMAC-SHA512(password=mnemonic, salt="mnemonic"+passphrase, iter=2048)
    Both mnemonic and passphrase are NFKD normalized.
    """
    mnemonic_norm = _normalize_phrase(mnemonic_phrase)
    passphrase_norm = _nfkd(passphrase or "")

    salt = _nfkd("mnemonic" + passphrase_norm).encode("utf-8")
    password = mnemonic_norm.encode("utf-8")

    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)
