"""
core.wsqk — Public API surface (stable imports)

WSQK (Wallet-Scoped Quantum Key) is the execution authority model.

This module re-exports the stable entrypoints used by the runtime orchestrator.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from .context_bind import (
    bind_scope_from_eqc,
    WSQKBindError,
)

from .executor import (
    execute_with_scope,
    WSQKExecutionError,
)

# Optional public types (safe to export if present)
try:
    from .scopes import WSQKScope  # type: ignore
except Exception:  # pragma: no cover
    WSQKScope = None  # type: ignore

try:
    from .session import WSQKSession, WSQKSessionError  # type: ignore
except Exception:  # pragma: no cover
    WSQKSession = None  # type: ignore
    WSQKSessionError = None  # type: ignore


__all__ = [
    "bind_scope_from_eqc",
    "WSQKBindError",
    "execute_with_scope",
    "WSQKExecutionError",
    "WSQKScope",
    "WSQKSession",
    "WSQKSessionError",
]
