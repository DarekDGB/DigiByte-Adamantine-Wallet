from __future__ import annotations

from dataclasses import dataclass
import secrets
import time
from typing import Optional


@dataclass(frozen=True)
class RuntimeCapability:
    """Unforgeable runtime capability used to authorize WSQK execution.

    This capability is bound to a specific WSQK scope hash (anti-confused-deputy)
    and can optionally expire (TTL) to avoid long-lived authority.
    """
    token: str
    scope_hash: str
    issued_at: int
    ttl_seconds: Optional[int] = None

    def is_expired(self, *, now: Optional[int] = None) -> bool:
        if self.ttl_seconds is None:
            return False
        now_ts = int(time.time()) if now is None else int(now)
        return now_ts > (int(self.issued_at) + int(self.ttl_seconds))

    def assert_valid(self, *, now: Optional[int] = None) -> None:
        if not self.token:
            raise ValueError("Runtime capability invalid: missing token")
        if not self.scope_hash:
            raise ValueError("Runtime capability invalid: missing scope_hash")
        if self.is_expired(now=now):
            raise ValueError("Runtime capability invalid: expired")


def issue_runtime_capability(
    *,
    scope_hash: str,
    ttl_seconds: Optional[int] = None,
    issued_at: Optional[int] = None,
) -> RuntimeCapability:
    """Mint a new capability token bound to a specific scope hash.

    Args:
        scope_hash: WSQK scope hash this capability is valid for.
        ttl_seconds: Optional TTL (seconds). If None, capability does not expire.
        issued_at: Optional override for deterministic tests.
    """
    ts = int(time.time()) if issued_at is None else int(issued_at)
    return RuntimeCapability(
        token=secrets.token_urlsafe(32),
        scope_hash=scope_hash,
        issued_at=ts,
        ttl_seconds=ttl_seconds,
    )
