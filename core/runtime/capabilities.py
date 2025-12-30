from __future__ import annotations

from dataclasses import dataclass
import secrets


@dataclass(frozen=True)
class RuntimeCapability:
    """Unforgeable runtime capability used to authorize WSQK execution."""
    token: str


def issue_runtime_capability() -> RuntimeCapability:
    """Mint a new capability token. Only runtime gates should call this."""
    return RuntimeCapability(token=secrets.token_urlsafe(32))
