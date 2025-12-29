"""
WSQK Scopes — Wallet-Scoped Quantum Key

Defines the WSQKScope object which binds authority to:

- wallet_id
- action
- context_hash (from EQC decision)
- time window (created_at/expires_at)

This is used to prevent replay / cross-context execution.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from hashlib import sha256
import json
import time


class WSQKScopeError(Exception):
    """Raised when WSQK scope validation fails."""
    pass


@dataclass(frozen=True)
class WSQKScope:
    wallet_id: str
    action: str
    context_hash: str

    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + 60)

    def is_active(self, now: Optional[int] = None) -> bool:
        t = int(now if now is not None else time.time())
        return self.created_at <= t <= self.expires_at

    def assert_active(self, now: Optional[int] = None) -> None:
        if not self.is_active(now=now):
            raise WSQKScopeError("WSQK scope is not active (expired or not yet valid).")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "action": self.action,
            "context_hash": self.context_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def scope_hash(self) -> str:
        """
        Stable hash of the scope itself.
        Used for binding nonces to a specific scope (anti-replay across scopes).
        """
        encoded = json.dumps(self.to_dict(), sort_keys=True).encode()
        return sha256(encoded).hexdigest()

    @staticmethod
    def from_ttl(*, wallet_id: str, action: str, context_hash: str, ttl_seconds: int = 60) -> "WSQKScope":
        now = int(time.time())
        return WSQKScope(
            wallet_id=wallet_id,
            action=action,
            context_hash=context_hash,
            created_at=now,
            expires_at=now + int(ttl_seconds),
        )

    def validate_wallet(self, wallet_id: str) -> None:
        if wallet_id != self.wallet_id:
            raise WSQKScopeError("WSQK wallet_id mismatch.")

    def validate_action(self, action: str) -> None:
        if (action or "").lower() != (self.action or "").lower():
            raise WSQKScopeError("WSQK action mismatch.")

    def validate_context(self, context_hash: str) -> None:
        if context_hash != self.context_hash:
            raise WSQKScopeError("WSQK context_hash mismatch.")
