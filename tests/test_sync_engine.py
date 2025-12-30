from core.wallet.keys.hdnode import HDNode
from core.wallet.account import WalletAccount
from core.wallet.state import WalletState
from core.wallet.sync import sync_account, UTXO


class FakeSyncProvider:
    def __init__(self, used: set[str], utxos_by_addr: dict[str, list[UTXO]]) -> None:
        self._used = used
        self._utxos = utxos_by_addr

    def is_used(self, address: str) -> bool:
        return address in self._used

    def list_utxos(self, address: str) -> list[UTXO]:
        return list(self._utxos.get(address, []))


def test_sync_account_collects_balance_and_utxos():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)

    state = WalletState.default()

    a0 = acc.receive_address_at(0)
    a1 = acc.receive_address_at(1)

    provider = FakeSyncProvider(
        used={a0, a1},
        utxos_by_addr={
            a0: [UTXO(txid="aa"*32, vout=0, value_sats=1000, address=a0)],
            a1: [UTXO(txid="bb"*32, vout=1, value_sats=2000, address=a1)],
        },
    )

    res = sync_account(provider, acc, state, max_scan=200)

    assert res.balance_sats == 3000
    assert len(res.utxos) == 2
    assert res.receive_last_used is not None
    assert res.scanned_receive >= state.gap_limit


def test_sync_account_no_used_addresses_returns_zero():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)
    acc = WalletAccount(root=root, coin_type=20, account=0)

    state = WalletState.default()

    provider = FakeSyncProvider(used=set(), utxos_by_addr={})
    res = sync_account(provider, acc, state, max_scan=200)

    assert res.balance_sats == 0
    assert res.utxos == []
    assert res.receive_last_used is None
    assert res.change_last_used is None
