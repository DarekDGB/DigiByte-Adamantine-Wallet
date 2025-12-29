"""
WSQK Session — Wallet-Scoped Quantum Key

Provides a minimal session container for WSQK executions:
- session_id
- TTL window
- one-time-use nonce (replay prevention)

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

    - wallet_id optionally binds a session to a wallet instance (used by integration tests)
    - created_at / expires_at define the allowed time window
    - used_nonces tracks one-time nonces within this session (in-memory v1)
    """

    wallet_id: Optional[str] = None

    ttl_seconds: int = 60
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(init=False)
    used_nonces: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.expires_at = self.created_at + int(self.ttl_seconds)

    def is_active(self, now: Optional[int] = None) -> bool:
        t = int(now if now is not None else time.time())
        return self.created_at <= t <= self.expires_at

    def assert_active(self, now: Optional[int] = None) -> None:
        if not self.is_active(now=now):
            raise WSQKSessionError("WSQK session is not active (expired or not yet valid).")

    def issue_nonce(self, now: Optional[int] = None) -> str:
        """
        Issue a new nonce for one-time execution.
        """
        self.assert_active(now=now)
        return str(uuid.uuid4())

    def consume_nonce(self, nonce: str, now: Optional[int] = None) -> None:
        """
        Mark a nonce as used. Reject re-use.
        """
        self.assert_active(now=now)

        n = (nonce or "").strip()
        if not n:
            raise WSQKSessionError("WSQK nonce is missing or empty.")

        if n in self.used_nonces:
            raise WSQKSessionError("WSQK nonce replay detected (nonce already used).")

        self.used_nonces.add(n)
