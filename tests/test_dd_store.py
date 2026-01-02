from core.storage.memory_store import MemoryWalletStorage
from core.dd.dd_store import DDStore, DDPosition, DDBalance, DDOutput


def test_dd_store_positions_save_load_delete_and_iter():
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

    assert store.load_position("pos-1") is None

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

    ids = sorted([p.position_id for p in store.iter_positions()])
    assert ids == ["pos-1", "pos-2"]

    store.delete_position("pos-1")
    assert store.load_position("pos-1") is None

    remaining = sorted([p.position_id for p in store.iter_positions()])
    assert remaining == ["pos-2"]


def test_dd_store_balances_set_get_and_iter():
    storage = MemoryWalletStorage()
    store = DDStore(storage)

    b1 = DDBalance(wallet_id="w1", account_id="a1", address="addr1", balance_minor=111)
    b2 = DDBalance(wallet_id="w1", account_id="a1", address="addr2", balance_minor=222)
    b_other = DDBalance(wallet_id="w1", account_id="a2", address="addrX", balance_minor=999)

    assert store.get_balance("w1", "a1", "addr1") is None

    store.set_balance(b1)
    store.set_balance(b2)
    store.set_balance(b_other)

    got = store.get_balance("w1", "a1", "addr1")
    assert got is not None
    assert got.balance_minor == 111

    got2 = store.get_balance("w1", "a1", "addr2")
    assert got2 is not None
    assert got2.balance_minor == 222

    # iter only for (w1,a1)
    balances = sorted([(b.address, b.balance_minor) for b in store.iter_balances("w1", "a1")])
    assert balances == [("addr1", 111), ("addr2", 222)]


def test_dd_store_outputs_save_load_and_iter():
    storage = MemoryWalletStorage()
    store = DDStore(storage)

    o1 = DDOutput(
        txid="tx1",
        vout=0,
        wallet_id="w1",
        account_id="a1",
        address="addr1",
        amount_minor=100,
        is_spent=False,
    )
    o2 = DDOutput(
        txid="tx2",
        vout=1,
        wallet_id="w1",
        account_id="a1",
        address="addr2",
        amount_minor=200,
        is_spent=True,
    )

    assert store.load_output("tx1", 0) is None

    store.save_output(o1)
    store.save_output(o2)

    got = store.load_output("tx1", 0)
    assert got is not None
    assert got.txid == "tx1"
    assert got.vout == 0
    assert got.amount_minor == 100
    assert got.is_spent is False

    outs = sorted([(o.txid, o.vout) for o in store.iter_outputs()])
    assert outs == [("tx1", 0), ("tx2", 1)]

    store.delete_output("tx1", 0)
    assert store.load_output("tx1", 0) is None
