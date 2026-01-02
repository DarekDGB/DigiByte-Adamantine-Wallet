import pytest
from pathlib import Path

from core.storage.sqlite_store import SQLiteWalletStorage


def test_sqlite_put_get_exists_delete(tmp_path: Path):
    db_path = tmp_path / "wallet.db"
    store = SQLiteWalletStorage(db_path)

    assert store.get("A") is None
    assert store.exists("A") is False

    store.put("A", {"v": 1})
    assert store.exists("A") is True
    assert store.get("A") == {"v": 1}

    store.delete("A")
    assert store.exists("A") is False
    assert store.get("A") is None

    store.close()


def test_sqlite_batch_commit(tmp_path: Path):
    db_path = tmp_path / "wallet.db"
    store = SQLiteWalletStorage(db_path)

    with store.begin_batch() as b:
        b.put("x", 1)
        b.put("y", {"n": 2})

    assert store.get("x") == 1
    assert store.get("y") == {"n": 2}

    store.close()


def test_sqlite_batch_rollback_on_exception(tmp_path: Path):
    db_path = tmp_path / "wallet.db"
    store = SQLiteWalletStorage(db_path)

    store.put("keep", 123)

    with pytest.raises(RuntimeError):
        with store.begin_batch() as b:
            b.put("keep", 999)
            b.put("temp", "nope")
            raise RuntimeError("boom")

    # unchanged due to rollback
    assert store.get("keep") == 123
    assert store.get("temp") is None

    store.close()


def test_sqlite_keys_prefix(tmp_path: Path):
    db_path = tmp_path / "wallet.db"
    store = SQLiteWalletStorage(db_path)

    store.put("DD_A", 1)
    store.put("DD_B", 2)
    store.put("EQC_X", 3)

    dd = set(store.keys(prefix="DD_"))
    assert dd == {"DD_A", "DD_B"}

    all_keys = set(store.keys())
    assert {"DD_A", "DD_B", "EQC_X"} <= all_keys

    store.close()
