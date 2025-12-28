"""
WalletState data models.

These models describe the in-memory view of:

- wallets
- accounts
- balances for DGB, DigiAssets, and DigiDollar (DD)

They are deliberately framework-agnostic so the same structures can be
used on Android / iOS / Web and in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Network(str, Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"
    REGTEST = "regtest"


class AssetKind(str, Enum):
    DGB = "DGB"
    DIGIASSET = "DGA"
    DIGIDOLLAR = "DD"


# ---------------------------------------------------------------------------
# Balance & asset views
# ---------------------------------------------------------------------------


@dataclass
class AssetBalance:
    """
    Generic balance view for any asset type.

    All amounts are stored as integers in "minor units":
      - DGB: satoshis-like minor units
      - DD: minimal indivisible DD units
      - DigiAssets: smallest indivisible units for that asset
    """

    asset_id: str               # e.g. "DGB", "DD", or DigiAsset ID
    kind: AssetKind
    confirmed: int = 0
    pending: int = 0
    locked: int = 0             # reserved for pending tx, staking, etc.

    @property
    def total(self) -> int:
        """Total balance including pending and locked."""
        return self.confirmed + self.pending + self.locked

    def apply_delta(self, confirmed_delta: int = 0, pending_delta: int = 0, locked_delta: int = 0) -> None:
        """
        Adjust balance by deltas. Used when building / confirming txs.
        """
        self.confirmed += confirmed_delta
        self.pending += pending_delta
        self.locked += locked_delta


# ---------------------------------------------------------------------------
# Account & wallet models
# ---------------------------------------------------------------------------


@dataclass
class AccountState:
    """
    Single logical account within a wallet.

    Examples:
      - "Main DGB account"
      - "Savings"
      - "Cold storage"
    """

    id: str
    label: str
    addresses: List[str] = field(default_factory=list)

    # Balances by asset_id ("DGB", "DD", or DigiAsset ID)
    balances: Dict[str, AssetBalance] = field(default_factory=dict)

    def get_balance(self, asset_id: str) -> AssetBalance:
        """
        Return an existing AssetBalance or create an empty one on demand.
        """
        if asset_id not in self.balances:
            # Heuristic: treat "DGB" specially, "DD" as DigiDollar, others as DigiAssets.
            if asset_id == "DGB":
                kind = AssetKind.DGB
            elif asset_id == "DD":
                kind = AssetKind.DIGIDOLLAR
            else:
                kind = AssetKind.DIGIASSET

            self.balances[asset_id] = AssetBalance(asset_id=asset_id, kind=kind)

        return self.balances[asset_id]

    def apply_dgb_delta(self, delta_minor: int) -> None:
        """
        Convenience helper for DGB balance updates.
        """
        bal = self.get_balance("DGB")
        bal.apply_delta(confirmed_delta=delta_minor)

    def apply_dd_delta(self, delta_units: int) -> None:
        """
        Convenience helper for DigiDollar (DD) balance updates.
        """
        bal = self.get_balance("DD")
        bal.apply_delta(confirmed_delta=delta_units)


@dataclass
class WalletMetadata:
    """
    Extra metadata that does not affect balances directly but is useful
    for Guardian, Shield, analytics, or UX.
    """

    guardian_profile: Optional[str] = None  # e.g. "conservative", "balanced", "aggressive"
    risk_profile: Optional[str] = None      # future hook for Risk Engine
    last_risk_sync_height: Optional[int] = None
    notes: Optional[str] = None


@dataclass
class WalletState:
    """
    Top-level wallet view.

    A single WalletState can contain multiple accounts, each with their
    own addresses and balances, on a given network.
    """

    id: str
    label: str
    network: Network = Network.MAINNET

    accounts: Dict[str, AccountState] = field(default_factory=dict)
    metadata: WalletMetadata = field(default_factory=WalletMetadata)

    # Sync / housekeeping
    last_sync_height: int = 0
    last_updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Account helpers
    # ------------------------------------------------------------------

    def get_account(self, account_id: str) -> AccountState:
        """
        Return an account, creating an empty one if it does not exist.

        This keeps flows simple in early prototypes; production code may
        decide to be stricter and raise if the account is missing.
        """
        if account_id not in self.accounts:
            self.accounts[account_id] = AccountState(id=account_id, label=account_id)
        return self.accounts[account_id]

    def ensure_account(self, account_id: str, label: Optional[str] = None) -> AccountState:
        """
        Ensure an account exists with an optional label override.
        """
        acc = self.get_account(account_id)
        if label and acc.label != label:
            acc.label = label
        return acc

    # ------------------------------------------------------------------
    # Balance helpers
    # ------------------------------------------------------------------

    def apply_dgb_delta(self, account_id: str, delta_minor: int) -> None:
        """
        Update DGB balance for a specific account.
        """
        acc = self.get_account(account_id)
        acc.apply_dgb_delta(delta_minor)
        self._touch()

    def apply_dd_delta(self, account_id: str, delta_units: int) -> None:
        """
        Update DigiDollar balance for a specific account.
        """
        acc = self.get_account(account_id)
        acc.apply_dd_delta(delta_units)
        self._touch()

    # ------------------------------------------------------------------
    # Snapshots / views
    # ------------------------------------------------------------------

    def snapshot_balances(self) -> Dict[str, Dict[str, int]]:
        """
        Return a simple serialisable snapshot:

        {
          "account_id": {
             "DGB": 12345,
             "DD": 1000,
             "ASSET-ID-1": 42,
             ...
          },
          ...
        }
        """
        result: Dict[str, Dict[str, int]] = {}
        for acc_id, acc in self.accounts.items():
            inner: Dict[str, int] = {}
            for asset_id, bal in acc.balances.items():
                inner[asset_id] = bal.confirmed
            result[acc_id] = inner
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _touch(self) -> None:
        """
        Update last_updated_at whenever we mutate balances or accounts.
        """
        self.last_updated_at = datetime.now(timezone.utc)
