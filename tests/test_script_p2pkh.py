import pytest

from core.wallet.tx.script import (
    script_pubkey_p2pkh,
    script_sig_p2pkh,
    ScriptError,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
)


def test_script_pubkey_p2pkh_layout() -> None:
    h160 = b"\x11" * 20
    spk = script_pubkey_p2pkh(h160)

    # OP_DUP OP_HASH160 PUSH20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    assert spk[0] == OP_DUP
    assert spk[1] == OP_HASH160
    assert spk[2] == 20
    assert spk[3:23] == h160
    assert spk[23] == OP_EQUALVERIFY
    assert spk[24] == OP_CHECKSIG
    assert len(spk) == 25


def test_script_sig_p2pkh_pushes_sig_and_pubkey() -> None:
    sig = b"\x30" * 70 + b"\x01"  # fake DER + hashtype (placeholder)
    pub = b"\x02" + b"\x22" * 32  # 33-byte compressed pubkey
    ss = script_sig_p2pkh(sig, pub)

    # First push is sig length
    assert ss[0] == len(sig)
    assert ss[1 : 1 + len(sig)] == sig

    # Then push pubkey
    off = 1 + len(sig)
    assert ss[off] == len(pub)
    assert ss[off + 1 : off + 1 + len(pub)] == pub


def test_invalid_lengths_raise() -> None:
    with pytest.raises(ScriptError):
        script_pubkey_p2pkh(b"\x00" * 19)

    with pytest.raises(ScriptError):
        script_sig_p2pkh(b"\x01", b"\x02" * 10)
