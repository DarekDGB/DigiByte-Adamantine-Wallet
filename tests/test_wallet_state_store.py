from core.storage.memory_store import MemoryWalletStorage
from core.wallet.state_store import WalletState, WalletStateStore


def test_wallet_state_store_save_load_delete():
    storage = MemoryWalletStorage()
    store = WalletStateStore(storage)

    state = WalletState(wallet_id="w1", created_at=1700000000, version=1, label="My Wallet")

    # initially missing
    assert store.exists("w1") is False
    assert store.load("w1") is None

    # save + load
    store.save(state)
    assert store.exists("w1") is True

    loaded = store.load("w1")
    assert loaded is not None
    assert loaded.wallet_id == "w1"
    assert loaded.created_at == 1700000000
    assert loaded.version == 1
    assert loaded.label == "My Wallet"

    # delete
    store.delete("w1")
    assert store.exists("w1") is False
    assert store.load("w1") is None
