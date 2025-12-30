from __future__ import annotations

from dataclasses import dataclass
from typing import List


class TxSerializeError(ValueError):
    pass


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "little", signed=False)


def _u64(n: int) -> bytes:
    return int(n).to_bytes(8, "little", signed=False)


def _varint(n: int) -> bytes:
    if n < 0:
        raise TxSerializeError("varint negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xFE" + n.to_bytes(4, "little")
    return b"\xFF" + n.to_bytes(8, "little")


def _rev32_hex(txid_hex: str) -> bytes:
    if len(txid_hex) != 64:
        raise TxSerializeError("txid must be 32 bytes hex")
    return bytes.fromhex(txid_hex)[::-1]


@dataclass(frozen=True)
class SignedInput:
    txid: str          # hex, big-endian
    vout: int
    script_sig: bytes
    sequence: int = 0xFFFFFFFF


@dataclass(frozen=True)
class SignedOutput:
    value_sats: int
    script_pubkey: bytes


@dataclass(frozen=True)
class SignedTransaction:
    version: int
    inputs: List[SignedInput]
    outputs: List[SignedOutput]
    locktime: int = 0


def serialize_signed_tx(tx: SignedTransaction) -> bytes:
    buf = bytearray()
    buf += _u32(tx.version)

    buf += _varint(len(tx.inputs))
    for i in tx.inputs:
        buf += _rev32_hex(i.txid)
        buf += int(i.vout).to_bytes(4, "little", signed=False)
        buf += _varint(len(i.script_sig))
        buf += i.script_sig
        buf += int(i.sequence).to_bytes(4, "little", signed=False)

    buf += _varint(len(tx.outputs))
    for o in tx.outputs:
        buf += _u64(o.value_sats)
        buf += _varint(len(o.script_pubkey))
        buf += o.script_pubkey

    buf += _u32(tx.locktime)
    return bytes(buf)


def serialize_signed_tx_hex(tx: SignedTransaction) -> str:
    return serialize_signed_tx(tx).hex()
