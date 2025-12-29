"""
WSQK Session — Wallet-Scoped Quantum Key

Provides a minimal session container for WSQK executions:
- wallet_id (optional, for integration clarity)
- session_id
- TTL window
- one-time-use nonces (replay prevention)

No cryptography is implemented here yet.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Set
import time
import uuid


class WSQKSessionError(Exception):
    """Raised when WSQK session constraints are violated."""
    pass


@dataclass
class WSQKSession:
    """
    WSQK session container.

    - created_at / expires_at define the allowed time window
    - used_nonces tracks one-time nonces within this session (in-memory v1)

    NOTE:
    We optionally bind nonce usage to a specific scope_hash to support
    stronger replay prevention semantics in integration tests.
    """
    wallet_id: Optional[str] = None

    ttl_seconds: int = 60
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(init=False)

    # stores keys like: "<scope_hash>:<nonce>" or just "<nonce>" (back-compat)
    used_nonces: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.expires_at = self.created_at + int(self.ttl_seconds)

    def is_active(self, now: Optional[int] = None) -> bool:
        t = int(now if now is not None else time.time())
        return self.created_at <= t <= self.expires_at

    def assert_active(self, now: Optional[int] = None) -> None:
        if not self.is_active(now=now):
            raise WSQKSessionError("WSQK session is not active (expired or not yet valid).")

    def issue_nonce(self, *, scope_hash: Optional[str] = None) -> str:
        """
        Issue a new nonce for one-time execution.

        scope_hash is optional (for binding nonce issuance/consumption to a scope).
        """
        # nonce itself is random; binding is enforced at consume-time
        return str(uuid.uuid4())

    def consume_nonce(self, nonce: str, *, scope_hash: Optional[str] = None, now: Optional[int] = None) -> None:
        """
        Mark a nonce as used. Reject re-use.

        If scope_hash is provided, we consume the tuple (scope_hash, nonce) to prevent
        replay of the same nonce under the same scope.
        """
        self.assert_active(now=now)

        key = f"{scope_hash}:{nonce}" if scope_hash else nonce
        if key in self.used_nonces:
            raise WSQKSessionError("WSQK nonce replay detected (nonce already used).")
        self.used_nonces.add(key)
