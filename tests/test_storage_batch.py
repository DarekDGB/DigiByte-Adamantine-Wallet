import pytest

from core.storage.interface import KeyNS
from core.storage.memory_store import MemoryWalletStorage


def test_basic_put_get_delete():
    store = MemoryWalletStorage()

    store.put("A", 123)
    assert store.get("A") == 123
    assert store.exists("A") is True

    store.delete("A")
    assert store.get("A") is None
    assert store.exists("A") is False


def test_batch_commit_is_atomic():
    store = MemoryWalletStorage()
    store.put("x", 1)

    with store.begin_batch() as batch:
        batch.put("x", 2)
        batch.put("y", 3)

    # after commit
    assert store.get("x") == 2
    assert store.get("y") == 3


def test_batch_rollback_on_exception():
    store = MemoryWalletStorage()
    store.put("x", 1)

    with pytest.raises(RuntimeError):
        with store.begin_batch() as batch:
            batch.put("x", 999)
            batch.put("y", 888)
            raise RuntimeError("boom")

    # state unchanged
    assert store.get("x") == 1
    assert store.get("y") is None


def test_namespaced_keys_do_not_collide():
    store = MemoryWalletStorage()

    dd = KeyNS("DD")
    eqc = KeyNS("EQC")

    store.put(dd.k("BALANCE"), 1000)
    store.put(eqc.k("VERDICT"), "ALLOW")

    assert store.get("DD_BALANCE") == 1000
    assert store.get("EQC_VERDICT") == "ALLOW"

    keys = list(store.keys())
    assert "DD_BALANCE" in keys
    assert "EQC_VERDICT" in keys


def test_prefix_key_iteration():
    store = MemoryWalletStorage()
    store.put("DD_A", 1)
    store.put("DD_B", 2)
    store.put("EQC_X", 3)

    dd_keys = list(store.keys(prefix="DD_"))
    assert set(dd_keys) == {"DD_A", "DD_B"}
