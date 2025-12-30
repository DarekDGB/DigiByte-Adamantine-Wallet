"""
Runtime Orchestrator — Adamantine Wallet OS

Enforces the core security invariant:

    EQC decides.
    WSQK executes.

No execution path may reach WSQK unless EQC (Equilibrium Confirmation)
returns VerdictType.ALLOW.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.eqc import (
    EQCEngine,
    EQCContext,
    VerdictType,
)

from core.runtime.capabilities import issue_runtime_capability

# WSQK is optional for now (scaffold integration)
from core.wsqk import (
    bind_scope_from_eqc,
    WSQKBindError,
    execute_with_scope,
    WSQKExecutionError,
)


class ExecutionBlocked(Exception):
    """Raised when execution is attempted without EQC approval."""
    pass


@dataclass
class OrchestratorResult:
    """Result returned after a successful EQC-gated execution."""
    context_hash: str
    result: Any


class RuntimeOrchestrator:
    """
    Enforces EQC → WSQK → execution flow.

    - If `use_wsqk=False` (default): runs `executor(context)` after EQC ALLOW.
    - If `use_wsqk=True`: binds a WSQK scope from EQC decision and executes under scope.
    """

    def __init__(self, eqc_engine: Optional[EQCEngine] = None):
        self._eqc = eqc_engine or EQCEngine()

    def execute(
        self,
        *,
        context: EQCContext,
        executor: Callable[[EQCContext], Any],
        use_wsqk: bool = False,
        wallet_id: Optional[str] = None,
        action: Optional[str] = None,
        ttl_seconds: int = 60,
    ) -> OrchestratorResult:
        decision = self._eqc.decide(context)

        if decision.verdict.type != VerdictType.ALLOW:
            raise ExecutionBlocked(f"Execution blocked by EQC: {decision.verdict.type}")

        # Default path (keeps existing behavior / tests)
        if not use_wsqk:
            result = executor(context)
            return OrchestratorResult(context_hash=decision.context_hash, result=result)

        # WSQK path (scope + context binding)
        if not wallet_id or not action:
            raise ValueError("wallet_id and action are required when use_wsqk=True")

        try:
            bound = bind_scope_from_eqc(
                decision=decision,
                wallet_id=wallet_id,
                action=action,
                ttl_seconds=ttl_seconds,
            )

            cap = issue_runtime_capability(scope_hash=bound.scope.scope_hash())

            exec_out = execute_with_scope(
                scope=bound.scope,
                context=context,
                wallet_id=wallet_id,
                action=action,
                executor=executor,
                capability=cap,
            )
        except (WSQKBindError, WSQKExecutionError) as e:
            raise ExecutionBlocked(f"WSQK execution blocked: {e}") from e

        return OrchestratorResult(
            context_hash=decision.context_hash,
            result=exec_out.result,
        )
