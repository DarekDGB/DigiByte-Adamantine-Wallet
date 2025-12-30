from __future__ import annotations

from core.wallet.tx.sighash import SIGHASH_ALL, plan_sighash_all
from core.wallet.keys.secp256k1 import ecdsa_sign


class ScriptSigError(ValueError):
    pass


def _push(data: bytes) -> bytes:
    """
    Minimal push for small elements.
    Supports lengths up to 75 bytes (enough for DER sig + pubkey).
    """
    if len(data) > 75:
        raise ScriptSigError("pushdata too large")
    return bytes([len(data)]) + data


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    # If highest bit set, prepend 0x00 to keep it positive
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def _der_encode_sig(r: int, s: int) -> bytes:
    """
    Minimal DER encoding for ECDSA signature (r,s).
    """
    rb = _der_int(r)
    sb = _der_int(s)
    seq = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(seq)]) + seq


def build_p2pkh_scriptsig(
    unsigned_tx,
    input_index: int,
    privkey_32: bytes,
    pubkey: bytes,
) -> bytes:
    """
    Build P2PKH scriptSig:
      <sig_der + sighash> <pubkey>

    NOTE: Uses plan_sighash_all() until raw tx serialization exists.
    """
    if len(privkey_32) != 32:
        raise ScriptSigError("privkey must be 32 bytes")

    # 1) Digest (plan-level)
    digest = plan_sighash_all(unsigned_tx, input_index, pubkey)

    # 2) Sign (r,s) -> DER
    r, s = ecdsa_sign(digest, privkey_32)
    sig_der = _der_encode_sig(r, s)

    # 3) Append sighash flag byte
    sig_with_type = sig_der + bytes([SIGHASH_ALL])

    # 4) scriptSig pushes
    return _push(sig_with_type) + _push(pubkey)
