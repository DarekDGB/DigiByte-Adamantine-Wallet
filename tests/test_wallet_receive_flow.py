from core.wallet.keys.hdnode import HDNode
from core.wallet.state import WalletState
from core.wallet.wallet import Wallet


def test_get_receive_address_does_not_advance() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    st = WalletState(receive_index=0)
    w = Wallet(root=root, state=st)

    a1 = w.get_receive_address()
    a2 = w.get_receive_address()

    assert a1 == a2
    assert w.state.receive_index == 0


def test_next_receive_address_advances_and_changes() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    st = WalletState(receive_index=0)
    w = Wallet(root=root, state=st)

    a0 = w.get_receive_address()
    a1 = w.next_receive_address()
    a2 = w.get_receive_address()

    assert a1 != a0
    assert a2 == a1
    assert w.state.receive_index == 1
