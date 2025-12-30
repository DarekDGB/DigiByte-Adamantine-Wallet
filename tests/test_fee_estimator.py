import pytest

from core.wallet.tx.fees import estimate_fee_sats, estimate_p2pkh_tx_vbytes, FeeError


def test_estimate_vbytes_known_formula() -> None:
    # 1-in 2-out typical spend
    assert estimate_p2pkh_tx_vbytes(1, 2) == 10 + 148 * 1 + 34 * 2

    # 2-in 2-out (consolidation spend)
    assert estimate_p2pkh_tx_vbytes(2, 2) == 10 + 148 * 2 + 34 * 2


def test_estimate_fee_is_vbytes_times_rate() -> None:
    v = estimate_p2pkh_tx_vbytes(1, 2)
    assert estimate_fee_sats(1, 2, sats_per_vbyte=1) == v
    assert estimate_fee_sats(1, 2, sats_per_vbyte=5) == v * 5


def test_invalid_inputs_raise() -> None:
    with pytest.raises(FeeError):
        estimate_p2pkh_tx_vbytes(0, 1)

    with pytest.raises(FeeError):
        estimate_p2pkh_tx_vbytes(-1, 1)

    with pytest.raises(FeeError):
        estimate_p2pkh_tx_vbytes(1, -1)

    with pytest.raises(FeeError):
        estimate_fee_sats(1, 2, 0)
