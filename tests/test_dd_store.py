from core.storage.memory_store import MemoryWalletStorage
from core.dd.dd_store import DDStore, DDPosition


def test_dd_store_save_load_delete_and_iter():
    storage = MemoryWalletStorage()
    store = DDStore(storage)

    p1 = DDPosition(
        position_id="pos-1",
        wallet_id="w1",
        account_id="a1",
        dgb_collateral=100_000,
        dd_minted=50_000,
        lock_tier=1,
        unlock_height=123456,
        is_active=True,
    )

    p2 = DDPosition(
        position_id="pos-2",
        wallet_id="w1",
        account_id="a1",
        dgb_collateral=200_000,
        dd_minted=100_000,
        lock_tier=2,
        unlock_height=223456,
        is_active=False,
    )

    # initially missing
    assert store.load_position("pos-1") is None

    # save + load
    store.save_position(p1)
    store.save_position(p2)

    loaded = store.load_position("pos-1")
    assert loaded is not None
    assert loaded.position_id == "pos-1"
    assert loaded.dgb_collateral == 100_000
    assert loaded.dd_minted == 50_000
    assert loaded.lock_tier == 1
    assert loaded.unlock_height == 123456
    assert loaded.is_active is True

    # iter positions (order not guaranteed)
    ids = sorted([p.position_id for p in store.iter_positions()])
    assert ids == ["pos-1", "pos-2"]

    # delete
    store.delete_position("pos-1")
    assert store.load_position("pos-1") is None

    remaining = sorted([p.position_id for p in store.iter_positions()])
    assert remaining == ["pos-2"]
