from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class BroadcastError(ValueError):
    pass


class Broadcaster(Protocol):
    """
    Network boundary (no real network here).
    Implementations later:
      - ElectrumBroadcaster
      - InsightBroadcaster
      - DGB Node RPC Broadcaster
    """

    def broadcast_rawtx(self, rawtx_hex: str) -> str:
        """
        Returns txid (hex) if accepted by the network.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class FakeBroadcaster:
    """
    CI-safe broadcaster used in tests.
    """
    accept: bool = True
    fake_txid: str = "00" * 32

    def broadcast_rawtx(self, rawtx_hex: str) -> str:
        if not isinstance(rawtx_hex, str) or len(rawtx_hex) == 0:
            raise BroadcastError("rawtx_hex required")
        if not self.accept:
            raise BroadcastError("broadcast rejected")
        return self.fake_txid
