"""
WSQK Guard — Wallet-Scoped Quantum Key

Single-use execution gate for WSQK.

Enforces:
- WSQKScope active + matches wallet/action/context
- WSQKSession active
- nonce is consumed exactly once (replay prevention)

No cryptography is implemented here yet.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.eqc.context import EQCContext
from core.runtime.capabilities import issue_runtime_capability
from .scopes import WSQKScope
from .session import WSQKSession, WSQKSessionError
from .executor import WSQKExecutionError, WSQKExecutionResult


class WSQKGuardError(Exception):
    """Raised when WSQK guarded execution cannot proceed safely."""
    pass


@dataclass(frozen=True)
class WSQKGuardedResult:
    scope: WSQKScope
    session_id: str
    nonce: str
    result: Any


def execute_guarded(
    *,
    scope: WSQKScope,
    session: WSQKSession,
    nonce: str,
    context: EQCContext,
    wallet_id: str,
    action: str,
    executor: Callable[[EQCContext], Any],
    now: Optional[int] = None,
) -> WSQKGuardedResult:
    """
    Enforce scope + session + nonce, then execute exactly once.
    """

    try:
        # 1) Session must be active
        session.assert_active(now=now)

        # 2) Nonce must be single-use
        session.consume_nonce(nonce, now=now)

        # 3) Scope must match and be active (uses context.context_hash())
        # Reuse existing executor validation to avoid duplicating rules
        exec_out: WSQKExecutionResult = _execute_with_scope_checked(
            scope=scope,
            context=context,
            wallet_id=wallet_id,
            action=action,
            executor=executor,
            now=now,
        )

    except (WSQKSessionError, WSQKExecutionError, ValueError) as e:
        raise WSQKGuardError(str(e)) from e

    return WSQKGuardedResult(
        scope=exec_out.scope,
        session_id=session.session_id,
        nonce=nonce,
        result=exec_out.result,
    )


def _execute_with_scope_checked(
    *,
    scope: WSQKScope,
    context: EQCContext,
    wallet_id: str,
    action: str,
    executor: Callable[[EQCContext], Any],
    now: Optional[int],
) -> WSQKExecutionResult:
    from .executor import execute_with_scope  # local import to keep dependencies tight

    cap = issue_runtime_capability()

    return execute_with_scope(
        scope=scope,
        context=context,
        wallet_id=wallet_id,
        action=action,
        executor=executor,
        capability=cap,
        now=now,
    )
