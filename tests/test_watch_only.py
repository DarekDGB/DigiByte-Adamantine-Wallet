import pytest

from core.wallet.watch import WatchOnlyAccount


class DummyDeriver:
    def pubkey_at(self, change: int, index: int) -> bytes:
        # Not real derivation — test scaffold only.
        # Just return a valid-looking compressed pubkey format:
        # 02/03 + 32 bytes
        prefix = b"\x02" if (change + index) % 2 == 0 else b"\x03"
        return prefix + (b"\x11" * 32)


def test_watch_only_can_sign_false():
    acc = WatchOnlyAccount(pubkey_deriver=DummyDeriver())
    assert acc.can_sign() is False


def test_watch_only_pubkey_shapes():
    acc = WatchOnlyAccount(pubkey_deriver=DummyDeriver())
    pk0 = acc.receive_pubkey(0)
    pk1 = acc.change_pubkey(1)

    assert len(pk0) == 33
    assert pk0[:1] in (b"\x02", b"\x03")

    assert len(pk1) == 33
    assert pk1[:1] in (b"\x02", b"\x03")
