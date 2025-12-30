from __future__ import annotations

from core.wallet.tx.sighash import plan_sighash_all, SIGHASH_ALL
from core.wallet.tx.signing import SigningError, sign_digest


class ScriptSigError(ValueError):
    pass


def _push(data: bytes) -> bytes:
    """
    Push raw bytes onto a script.
    Supports data lengths up to 75 bytes (enough for sig + pubkey).
    """
    if len(data) > 75:
        raise ScriptSigError("pushdata too large")
    return bytes([len(data)]) + data


def build_p2pkh_scriptsig(
    unsigned_tx,
    input_index: int,
    privkey_32: bytes,
    pubkey: bytes,
) -> bytes:
    """
    Build P2PKH scriptSig:
      <sig + sighash> <pubkey>

    NOTE: Uses plan_sighash_all() until raw tx serialization exists.
    """
    if len(privkey_32) != 32:
        raise ScriptSigError("privkey must be 32 bytes")

    # 1) Compute digest (plan-level for now)
    digest = plan_sighash_all(unsigned_tx, input_index, pubkey)

    # 2) Sign digest (DER)
    try:
        sig_der = sign_digest(privkey_32, digest)
    except SigningError as e:
        raise ScriptSigError(str(e)) from e

    # 3) Append sighash flag
    sig_with_type = sig_der + bytes([SIGHASH_ALL])

    # 4) Build scriptSig
    return _push(sig_with_type) + _push(pubkey)
