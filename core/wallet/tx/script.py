from __future__ import annotations


class ScriptError(ValueError):
    pass


# Opcodes (only what we need for P2PKH)
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC


def _push_data(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise ScriptError("data must be bytes")
    b = bytes(data)
    n = len(b)
    if n > 75:
        raise ScriptError("push_data supports up to 75 bytes (minimal)")
    return bytes([n]) + b


def script_pubkey_p2pkh(pubkey_hash160: bytes) -> bytes:
    """
    scriptPubKey for P2PKH:
    OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    if not isinstance(pubkey_hash160, (bytes, bytearray)):
        raise ScriptError("pubkey_hash160 must be bytes")
    h = bytes(pubkey_hash160)
    if len(h) != 20:
        raise ScriptError("pubkey_hash160 must be 20 bytes")
    return bytes([OP_DUP, OP_HASH160]) + _push_data(h) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def script_sig_p2pkh(sig_with_hashtype: bytes, pubkey: bytes) -> bytes:
    """
    scriptSig for P2PKH:
    <sig+hashtype> <pubkey>
    """
    if not isinstance(sig_with_hashtype, (bytes, bytearray)):
        raise ScriptError("signature must be bytes")
    if not isinstance(pubkey, (bytes, bytearray)):
        raise ScriptError("pubkey must be bytes")

    s = bytes(sig_with_hashtype)
    p = bytes(pubkey)

    if len(p) not in (33, 65):
        raise ScriptError("pubkey must be 33 or 65 bytes")

    return _push_data(s) + _push_data(p)
