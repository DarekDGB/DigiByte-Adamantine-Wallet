import pytest

from core.storage.memory_store import MemoryWalletStorage
from core.wallet.account_store import AccountStore
from core.wallet.account_factory import AccountFactory


def test_account_factory_creates_account_and_persists_watch_only():
    storage = MemoryWalletStorage()
    store = AccountStore(storage)
    factory = AccountFactory(store)

    acc = factory.create_account(
        wallet_id="w1",
        account_id="a1",
        index=0,
        watch_only=True,
        label="Watch Account",
    )

    assert acc.wallet_id == "w1"
    assert acc.account_id == "a1"
    assert acc.index == 0
    assert acc.watch_only is True
    assert acc.label == "Watch Account"

    # persisted
    loaded = store.load("w1", "a1")
    assert loaded is not None
    assert loaded.watch_only is True
    assert store.is_watch_only("w1", "a1") is True


def test_account_factory_rejects_duplicates():
    storage = MemoryWalletStorage()
    store = AccountStore(storage)
    factory = AccountFactory(store)

    factory.create_account(wallet_id="w1", account_id="a1", index=0)

    with pytest.raises(ValueError):
        factory.create_account(wallet_id="w1", account_id="a1", index=0)
