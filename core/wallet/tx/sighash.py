from __future__ import annotations

import hashlib

from core.wallet.tx.script import script_pubkey_p2pkh
from core.wallet.address import hash160


class SighashError(ValueError):
    pass


SIGHASH_ALL = 0x01


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def legacy_sighash_all(unsigned_tx, input_index: int, pubkey: bytes) -> bytes:
    """
    Compute legacy SIGHASH_ALL digest for a single P2PKH input.

    unsigned_tx:
      - version
      - inputs: list(txid, vout)
      - outputs
      - locktime

    pubkey:
      compressed or uncompressed pubkey for the input being signed
    """
    if input_index < 0 or input_index >= len(unsigned_tx.inputs):
        raise SighashError("input_index out of range")

    pubkey_hash160 = hash160(pubkey)
    script_code = script_pubkey_p2pkh(pubkey_hash160)

    buf = bytearray()

    # version
    buf += _u32(unsigned_tx.version)

    # inputs
    buf += encode_varint(len(unsigned_tx.inputs))
    for i, inp in enumerate(unsigned_tx.inputs):
        buf += bytes.fromhex(inp.txid)[::-1]
        buf += _u32(inp.vout)

        if i == input_index:
            buf += encode_varint(len(script_code))
            buf += script_code
        else:
            buf += b"\x00"

        buf += _u32(inp.sequence)

    # outputs
    buf += encode_varint(len(unsigned_tx.outputs))
    for out in unsigned_tx.outputs:
        buf += _u64(out.value_sats)
        buf += encode_varint(len(out.script_pubkey))
        buf += out.script_pubkey

    # locktime
    buf += _u32(unsigned_tx.locktime)

    # sighash type
    buf += _u32(SIGHASH_ALL)

    return double_sha256(bytes(buf))


def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")
