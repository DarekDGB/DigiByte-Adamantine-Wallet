"""
WalletState (non-secret state)

This stores ONLY safe wallet metadata needed for UX and deterministic address flow.
No seeds, no mnemonics, no private keys.

Fields:
- network: "mainnet" (testnet later)
- coin_type: SLIP-0044 coin type (DigiByte = 20)
- account: BIP44 account index (default 0)
- receive_index: next receive index (external chain /0)
- change_index: next change index (internal chain /1)
- gap_limit: discovery gap limit (default 20)
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, Literal


Network = Literal["mainnet", "testnet"]


class WalletStateError(ValueError):
    pass


@dataclass(frozen=True)
class WalletState:
    network: Network = "mainnet"
    coin_type: int = 20
    account: int = 0
    receive_index: int = 0
    change_index: int = 0
    gap_limit: int = 20

    def __post_init__(self) -> None:
        if self.network not in ("mainnet", "testnet"):
            raise WalletStateError("Invalid network.")
        if self.coin_type < 0:
            raise WalletStateError("coin_type must be >= 0.")
        if self.account < 0:
            raise WalletStateError("account must be >= 0.")
        if self.receive_index < 0:
            raise WalletStateError("receive_index must be >= 0.")
        if self.change_index < 0:
            raise WalletStateError("change_index must be >= 0.")
        if self.gap_limit <= 0:
            raise WalletStateError("gap_limit must be > 0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network": self.network,
            "coin_type": self.coin_type,
            "account": self.account,
            "receive_index": self.receive_index,
            "change_index": self.change_index,
            "gap_limit": self.gap_limit,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WalletState":
        # Use defaults if missing (forward compatible)
        return cls(
            network=data.get("network", "mainnet"),
            coin_type=int(data.get("coin_type", 20)),
            account=int(data.get("account", 0)),
            receive_index=int(data.get("receive_index", 0)),
            change_index=int(data.get("change_index", 0)),
            gap_limit=int(data.get("gap_limit", 20)),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> "WalletState":
        try:
            data = json.loads(s)
        except json.JSONDecodeError as e:
            raise WalletStateError("Invalid JSON.") from e
        if not isinstance(data, dict):
            raise WalletStateError("WalletState JSON must be an object.")
        return cls.from_dict(data)
