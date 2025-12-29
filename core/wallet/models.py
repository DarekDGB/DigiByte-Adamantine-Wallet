"""
Wallet models (scaffold)

TODO:
- Finalize network enum(s)
- Add tx serialization fields
- Add account / derivation path models
"""

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class Network:
    name: str  # TODO: use enum later


@dataclass(frozen=True)
class Address:
    value: str
    network: Network


@dataclass(frozen=True)
class UTXO:
    txid: str
    vout: int
    value_sats: int
    script_pubkey_hex: str
    address: Address


@dataclass(frozen=True)
class TxOutput:
    address: Address
    value_sats: int


@dataclass(frozen=True)
class UnsignedTx:
    inputs: Sequence[UTXO]
    outputs: Sequence[TxOutput]
    fee_sats: int


@dataclass(frozen=True)
class SignedTx:
    raw_hex: str
    txid: Optional[str] = None
