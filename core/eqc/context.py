"""
EQC Context — Equilibrium Confirmation

Context is the immutable snapshot of conditions under which an action
is requested inside Adamantine Wallet OS.

EQC (Equilibrium Confirmation) decisions must be based ONLY on data present
in this Context. No hidden globals. No side effects.

This context may be hashed (`context_hash()`) for:
- audit logs
- replay protection
- downstream binding (WSQK scopes), only after EQC returns ALLOW

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from hashlib import sha256
import json
import time


@dataclass(frozen=True)
class DeviceContext:
    # Optional so tests + callers can omit it
    device_id: Optional[str] = None

    device_type: str = "mobile"     # mobile, hardware, airgap, browser, extension, etc.
    os: str = "ios"                 # ios, android, linux
    trusted: bool = False
    first_seen_ts: Optional[int] = None

    # Required by WSQK enforcement tests
    app_version: Optional[str] = None


@dataclass(frozen=True)
class NetworkContext:
    # Keep your original idea (network name)
    network: str = "mainnet"        # mainnet, testnet

    # Fields required by WSQK enforcement tests
    node_type: Optional[str] = None         # local, digimobile, remote
    node_trusted: bool = False
    entropy_score: Optional[float] = None

    # Shared fields
    fee_rate: Optional[int] = None
    peer_count: Optional[int] = None


@dataclass(frozen=True)
class UserContext:
    user_id: Optional[str] = None
    biometric_available: bool = False
    pin_set: bool = False


@dataclass(frozen=True)
class ActionContext:
    action: str                     # send, mint, redeem, sign, vote
    asset: str                      # DGB, DigiAsset, DigiDollar
    amount: Optional[int] = None
    recipient: Optional[str] = None


@dataclass(frozen=True)
class EQCContext:
    """
    Canonical context passed into EQC.

    This object is hashed and may be bound to WSQK scopes later.
    """
    action: ActionContext
    device: DeviceContext
    network: NetworkContext
    user: UserContext
    timestamp: int = field(default_factory=lambda: int(time.time()))
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.__dict__,
            "device": self.device.__dict__,
            "network": self.network.__dict__,
            "user": self.user.__dict__,
            "timestamp": self.timestamp,
            "extra": dict(self.extra),
        }

    def context_hash(self) -> str:
        """
        Stable hash of the context used for:
        - audit logs
        - WSQK binding
        - replay protection
        """
        encoded = json.dumps(self.to_dict(), sort_keys=True).encode()
        return sha256(encoded).hexdigest()
