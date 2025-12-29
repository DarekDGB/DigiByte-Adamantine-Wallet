"""
Mnemonic (BIP39) scaffold

TODO:
- Implement BIP39 wordlist + entropy->words + checksum validation
- Implement seed derivation (PBKDF2-HMAC-SHA512)
"""

from dataclasses import dataclass
from typing import List

from ..errors import NotImplementedYet


@dataclass(frozen=True)
class Mnemonic:
    words: List[str]

    @property
    def phrase(self) -> str:
        return " ".join(self.words)


def from_phrase(phrase: str) -> Mnemonic:
    words = [w for w in phrase.strip().split() if w]
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("Mnemonic must be 12/15/18/21/24 words.")
    return Mnemonic(words=words)


def generate(strength_bits: int = 128) -> Mnemonic:
    raise NotImplementedYet("TODO: implement BIP39 mnemonic generation.")
