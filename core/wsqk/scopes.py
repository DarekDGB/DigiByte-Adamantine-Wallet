"""
WSQK Scopes — Wallet-Scoped Quantum Key

Defines an immutable, time-bounded execution authority ("scope") that is:

- wallet-scoped
- action-scoped
- context-hash bound (EQC context_hash)
- time-limited (not_before .. expires_at)
- hashable (scope_hash) for session/nonce binding

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Optional
import json
import time


class WSQKScopeError(Exception):
    """Raised when WSQK scope constraints are violated."""
    pass


@dataclass(frozen=True)
class WSQKScope:
    """
    Immutable WSQK authority token.

    Tests expect:
      - fields: wallet_id, action, context_hash, not_before, expires_at
      - methods: is_active, assert_active, assert_wallet, assert_action, assert_context
      - methods: scope_hash, from_ttl
    """
    wallet_id: str
    action: str
    context_hash: str
    not_before: int
    expires_at: int

    def is_active(self, now: Optional[int] = None) -> bool:
        t = int(now if now is not None else time.time())
        return self.not_before <= t <= self.expires_at

    def assert_active(self, now: Optional[int] = None) -> None:
        if not self.is_active(now=now):
            raise WSQKScopeError("WSQK scope is not active (expired or not yet valid).")

    def assert_wallet(self, wallet_id: str) -> None:
        if wallet_id != self.wallet_id:
            raise WSQKScopeError("WSQK scope wallet_id mismatch.")

    def assert_action(self, action: str) -> None:
        if (action or "").lower() != (self.action or "").lower():
            raise WSQKScopeError("WSQK scope action mismatch.")

    def assert_context(self, context_hash: str) -> None:
        if context_hash != self.context_hash:
            raise WSQKScopeError("WSQK scope context_hash mismatch.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "action": self.action,
            "context_hash": self.context_hash,
            "not_before": int(self.not_before),
            "expires_at": int(self.expires_at),
        }

    def scope_hash(self) -> str:
        """
        Stable hash used for nonce binding / audit.
        """
        encoded = json.dumps(self.to_dict(), sort_keys=True).encode()
        return sha256(encoded).hexdigest()

    @staticmethod
    def from_ttl(
        *,
        wallet_id: str,
        action: str,
        context_hash: str,
        ttl_seconds: int = 60,
        now: Optional[int] = None,
    ) -> "WSQKScope":
        t = int(now if now is not None else time.time())
        ttl = int(ttl_seconds)
        if ttl <= 0:
            raise ValueError("ttl_seconds must be > 0")
        return WSQKScope(
            wallet_id=wallet_id,
            action=action,
            context_hash=context_hash,
            not_before=t,
            expires_at=t + ttl,
        )
