from core.storage.memory_store import MemoryWalletStorage
from core.wallet.state_store import WalletState, WalletStateStore
from core.wallet.account_store import AccountStore
from core.wallet.account_factory import AccountFactory
from core.wallet.query_api import WalletQueryAPI
from core.dd.dd_store import DDStore, DDBalance


def test_query_api_lists_accounts_and_summary():
    storage = MemoryWalletStorage()

    # wallet state
    wallet_store = WalletStateStore(storage)
    wallet_store.save(
        WalletState(wallet_id="w1", created_at=1700000000, label="Main Wallet")
    )

    # accounts
    account_store = AccountStore(storage)
    factory = AccountFactory(account_store)

    factory.create_account(wallet_id="w1", account_id="a1", index=0, watch_only=False)
    factory.create_account(wallet_id="w1", account_id="a2", index=1, watch_only=True)

    api = WalletQueryAPI(storage)

    accounts = api.list_accounts("w1")
    assert len(accounts) == 2
    assert accounts[0].account_id == "a1"
    assert accounts[1].account_id == "a2"

    summary = api.get_wallet_summary("w1")
    assert summary.wallet_id == "w1"
    assert summary.label == "Main Wallet"
    assert summary.account_count == 2
    assert summary.watch_only_count == 1


def test_query_api_lists_dd_balances():
    storage = MemoryWalletStorage()

    dd_store = DDStore(storage)
    dd_store.set_balance(
        DDBalance(wallet_id="w1", account_id="a1", address="addr1", balance_minor=100)
    )
    dd_store.set_balance(
        DDBalance(wallet_id="w1", account_id="a1", address="addr2", balance_minor=200)
    )
    dd_store.set_balance(
        DDBalance(wallet_id="w1", account_id="a2", address="addrX", balance_minor=999)
    )

    api = WalletQueryAPI(storage)

    balances = api.list_dd_balances("w1", "a1")
    balances = sorted([(b.address, b.balance_minor) for b in balances])

    assert balances == [("addr1", 100), ("addr2", 200)]
