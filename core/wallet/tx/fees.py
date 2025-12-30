from __future__ import annotations


class FeeError(ValueError):
    pass


def estimate_p2pkh_tx_vbytes(num_inputs: int, num_outputs: int) -> int:
    """
    Rough vbytes estimate for a legacy (non-SegWit) P2PKH transaction.

    Common rule of thumb:
      vbytes ~= 10 + 148*inputs + 34*outputs

    This is good enough for fee estimation and deterministic tests.
    """
    if num_inputs < 0:
        raise FeeError("num_inputs must be >= 0")
    if num_outputs < 0:
        raise FeeError("num_outputs must be >= 0")
    if num_inputs == 0:
        # no such thing as a meaningful tx with 0 inputs
        raise FeeError("num_inputs must be > 0")

    return 10 + 148 * num_inputs + 34 * num_outputs


def estimate_fee_sats(num_inputs: int, num_outputs: int, sats_per_vbyte: int) -> int:
    """
    Fee estimate in satoshis using the P2PKH vbytes estimate.
    """
    if sats_per_vbyte <= 0:
        raise FeeError("sats_per_vbyte must be > 0")

    vbytes = estimate_p2pkh_tx_vbytes(num_inputs, num_outputs)
    return vbytes * sats_per_vbyte
