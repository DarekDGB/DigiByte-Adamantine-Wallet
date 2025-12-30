"""
WSQK Executor — Wallet-Scoped Quantum Key

Execution stub for WSQK.

This module provides a minimal, explicit interface that:
- validates a WSQKScope
- ensures context_hash + action + wallet_id match
- then runs a provided callable (future: signing / authorization)

No cryptography is implemented here yet.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.eqc.context import EQCContext
from core.runtime.capabilities import RuntimeCapability
from .scopes import WSQKScope


class WSQKExecutionError(Exception):
    """Raised when WSQK execution cannot proceed safely."""
    pass


@dataclass(frozen=True)
class WSQKExecutionResult:
    """
    Result of a WSQK-gated execution.
    """
    scope: WSQKScope
    result: Any


def execute_with_scope(
    *,
    scope: WSQKScope,
    context: EQCContext,
    wallet_id: str,
    action: str,
    executor: Callable[[EQCContext], Any],
    capability: RuntimeCapability | None = None,
    now: Optional[int] = None,
) -> WSQKExecutionResult:
    """
    Enforce scope constraints, then execute.

    This is the minimal WSQK "execution gate" that will later wrap real signing.

    Invariant:
        WSQK MUST NOT execute without a valid runtime capability.
    """
    if not capability or not getattr(capability, "token", None):
        raise WSQKExecutionError("WSQK execution denied: missing runtime capability")

    try:
        scope.assert_active(now=now)
        scope.assert_wallet(wallet_id)
        scope.assert_action(action)
        scope.assert_context(context.context_hash())
    except Exception as e:
        raise WSQKExecutionError(str(e)) from e

    return WSQKExecutionResult(scope=scope, result=executor(context))
