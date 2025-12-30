from core.wallet.state import WalletState, WalletStateError


def test_wallet_state_defaults() -> None:
    st = WalletState()
    assert st.network == "mainnet"
    assert st.coin_type == 20
    assert st.account == 0
    assert st.receive_index == 0
    assert st.change_index == 0
    assert st.gap_limit == 20


def test_wallet_state_roundtrip_json() -> None:
    st1 = WalletState(network="mainnet", coin_type=20, account=0, receive_index=7, change_index=3, gap_limit=25)
    s = st1.to_json()
    st2 = WalletState.from_json(s)
    assert st2 == st1


def test_wallet_state_from_json_with_missing_fields_uses_defaults() -> None:
    st = WalletState.from_json('{"receive_index":2}')
    assert st.network == "mainnet"
    assert st.coin_type == 20
    assert st.account == 0
    assert st.receive_index == 2
    assert st.change_index == 0
    assert st.gap_limit == 20


def test_wallet_state_validation() -> None:
    try:
        WalletState(gap_limit=0)
        assert False, "Expected WalletStateError"
    except WalletStateError:
        pass

    try:
        WalletState(receive_index=-1)
        assert False, "Expected WalletStateError"
    except WalletStateError:
        pass

    try:
        WalletState(network="invalid")  # type: ignore[arg-type]
        assert False, "Expected WalletStateError"
    except WalletStateError:
        pass
