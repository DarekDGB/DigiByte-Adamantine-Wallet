import pytest

from core.wallet.tx.broadcast import FakeBroadcaster, BroadcastError


def test_fake_broadcaster_accepts() -> None:
    b = FakeBroadcaster(accept=True, fake_txid="11" * 32)
    txid = b.broadcast_rawtx("deadbeef")
    assert txid == "11" * 32


def test_fake_broadcaster_rejects() -> None:
    b = FakeBroadcaster(accept=False)
    with pytest.raises(BroadcastError):
        b.broadcast_rawtx("deadbeef")
