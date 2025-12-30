from __future__ import annotations

import hashlib

from core.wallet.address import hash160
from core.wallet.tx.script import script_pubkey_p2pkh

SIGHASH_ALL = 0x01


class SighashError(ValueError):
    pass


def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "little", signed=False)


def _u64(n: int) -> bytes:
    return int(n).to_bytes(8, "little", signed=False)


def _varbytes(b: bytes) -> bytes:
    return encode_varint(len(b)) + b


def encode_varint(n: int) -> bytes:
    n = int(n)
    if n < 0:
        raise SighashError("varint cannot be negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def plan_sighash_all(unsigned_tx, input_index: int, pubkey: bytes) -> bytes:
    """
    Deterministic signing digest for the current UnsignedTransaction *plan* model.

    This is NOT a raw legacy tx sighash yet because the plan model does not carry
    version/locktime/sequence/scriptPubKey bytes.

    It is intentionally:
    - deterministic
    - input-index specific
    - bound to all prevouts + all outputs + fee
    - bound to the P2PKH scriptPubKey derived from pubkey

    When we add raw serialization in Phase 9.5, we will replace this with the
    real legacy SIGHASH_ALL algorithm.
    """
    if input_index < 0 or input_index >= len(unsigned_tx.inputs):
        raise SighashError("input_index out of range")

    # Bind to scriptCode (P2PKH) derived from the pubkey (so sig != reusable)
    h160 = hash160(pubkey)
    script_code = script_pubkey_p2pkh(h160)

    buf = bytearray()
    buf += b"ADAMANTINE_PLAN_SIGHASH_V1"

    # inputs (prevouts + address string)
    buf += encode_varint(len(unsigned_tx.inputs))
    for txin in unsigned_tx.inputs:
        prev = txin.prevout
        txid_hex = prev.txid
        if not isinstance(txid_hex, str) or len(txid_hex) != 64:
            raise SighashError("prevout.txid must be 32-byte hex")
        buf += bytes.fromhex(txid_hex)
        buf += _u32(prev.vout)

        # include the funding address string (ties plan to wallet path)
        addr = txin.address
        if not isinstance(addr, str):
            raise SighashError("input.address must be str")
        buf += _varbytes(addr.encode("utf-8"))

    # outputs (address + value)
    buf += encode_varint(len(unsigned_tx.outputs))
    for out in unsigned_tx.outputs:
        if not isinstance(out.address, str):
            raise SighashError("output.address must be str")
        buf += _varbytes(out.address.encode("utf-8"))
        buf += _u64(out.value_sats)

    # fee + index + script_code + sighash flag
    buf += _u64(unsigned_tx.fee_sats)
    buf += _u32(input_index)
    buf += _varbytes(script_code)
    buf += _u32(SIGHASH_ALL)

    return double_sha256(bytes(buf))
