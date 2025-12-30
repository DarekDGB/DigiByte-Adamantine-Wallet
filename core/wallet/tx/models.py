from __future__ import annotations

from dataclasses import dataclass
from typing import List


class TxModelError(ValueError):
    pass


@dataclass(frozen=True)
class OutPoint:
    txid: str  # hex string (64 chars)
    vout: int  # output index


@dataclass(frozen=True)
class TxInput:
    prevout: OutPoint
    value_sats: int
    address: str


@dataclass(frozen=True)
class TxOutput:
    address: str
    value_sats: int


@dataclass(frozen=True)
class UnsignedTransaction:
    inputs: List[TxInput]
    outputs: List[TxOutput]
    fee_sats: int

    def total_in(self) -> int:
        return sum(i.value_sats for i in self.inputs)

    def total_out(self) -> int:
        return sum(o.value_sats for o in self.outputs)

    def sanity_check(self) -> None:
        if self.fee_sats < 0:
            raise TxModelError("fee_sats must be >= 0")
        if not self.inputs:
            raise TxModelError("transaction must have at least one input")
        if not self.outputs:
            raise TxModelError("transaction must have at least one output")
        for i in self.inputs:
            if i.value_sats <= 0:
                raise TxModelError("input value must be > 0")
            if i.prevout.vout < 0:
                raise TxModelError("vout must be >= 0")
            if not i.prevout.txid or len(i.prevout.txid) != 64:
                raise TxModelError("txid must be 64 hex chars")
        for o in self.outputs:
            if o.value_sats <= 0:
                raise TxModelError("output value must be > 0")
        if self.total_in() < self.total_out() + self.fee_sats:
            raise TxModelError("insufficient total input for outputs + fee")
