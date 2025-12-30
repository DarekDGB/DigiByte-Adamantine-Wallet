from __future__ import annotations

from dataclasses import dataclass
import secrets


@dataclass(frozen=True)
class RuntimeCapability:
    """Unforgeable runtime capability used to authorize WSQK execution.

    This capability is bound to a specific WSQK scope hash to prevent reuse
    across different scopes (anti-confused-deputy).
    """
    token: str
    scope_hash: str


def issue_runtime_capability(*, scope_hash: str) -> RuntimeCapability:
    """Mint a new capability token bound to a specific scope hash."""
    return RuntimeCapability(
        token=secrets.token_urlsafe(32),
        scope_hash=scope_hash,
    )
