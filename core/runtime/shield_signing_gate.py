"""
Shield Signing Gate — Adamantine Wallet OS

This module turns the Shield (5-layer defense + Adaptive Core) into an
**authoritative runtime gate** for any private-key operation.

Core invariant introduced here:

    No signing-like execution may proceed unless:
        EQC verdict is ALLOW
        AND Shield decision is not BLOCK

Notes:
- This file is intentionally lightweight and test-friendly.
- It does not implement real cryptography; it enforces decision flow.
- The default Shield evaluator is a SAFE no-op allow, so wiring this in
  will not break existing behaviour until you enable stricter layers.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from core.eqc import EQCEngine
from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.runtime.orchestrator import ExecutionBlocked
from core.wsqk.context_bind import bind_scope_from_eqc
from core.wsqk.executor import execute_with_scope
from core.shield_bridge_client import ShieldBridgeClient, ShieldDecision


@dataclass(frozen=True)
class SigningIntent:
    """A minimal, auditable request to perform a signing-like action.

    IMPORTANT:
    - No secrets here (no private keys, no seed bytes).
    - The intent is safe to log (or hash) for audit purposes.
    """

    wallet_id: str
    account_id: str
    action: str = "sign"
    asset: str = "DGB"
    amount: Optional[int] = None
    recipient: Optional[str] = None
    to_address: Optional[str] = None
    amount_minor: Optional[int] = None

    # Optional context metadata (kept simple for v0.2)
    device_type: str = "mobile"
    platform: str = "ios"
    network_type: str = "unknown"
    user_id: str = "user"
    extra: Dict[str, Any] = field(default_factory=dict)


class ShieldEvaluator:
    """Interface-like callable wrapper for Shield evaluation."""

    def evaluate(self, intent: SigningIntent) -> ShieldDecision:  # pragma: no cover
        raise NotImplementedError


class DefaultShieldEvaluator(ShieldEvaluator):
    """Default evaluator that delegates to ShieldBridgeClient (safe allow)."""

    def __init__(self, client: Optional[ShieldBridgeClient] = None) -> None:
        self._client = client or ShieldBridgeClient()

    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        # Route to existing safe methods where possible.
        if (
            intent.action.lower() in {"send", "send_dgb", "transfer"}
            and intent.to_address
            and intent.amount_minor is not None
        ):
            return self._client.evaluate_send_dgb(
                wallet_id=intent.wallet_id,
                account_id=intent.account_id,
                to_address=intent.to_address,
                amount_minor=intent.amount_minor,
                meta={"source": "shield_signing_gate"},
            )
        # Generic signing operation (default allow for now)
        return ShieldDecision.allow(reason="shield_gate_default_allow")


def _build_eqc_context(intent: SigningIntent) -> EQCContext:
    """Build an EQCContext from a SigningIntent."""
    action = ActionContext(
        action=intent.action,
        asset=intent.asset,
        amount=intent.amount,
        recipient=intent.recipient or intent.to_address,
    )

    device = DeviceContext(
        device_id=str(intent.extra.get("device_id", "device")),
        device_type=intent.device_type,
        os=intent.platform,
        trusted=bool(intent.extra.get("device_trusted", False)),
        app_version=str(intent.extra.get("app_version", "")) or None,
    )

    network = NetworkContext(
        network=intent.network_type or "mainnet",
        node_type=str(intent.extra.get("node_type", "")) or None,
        node_trusted=bool(intent.extra.get("node_trusted", False)),
        entropy_score=float(intent.extra.get("entropy_score"))
        if intent.extra.get("entropy_score") is not None
        else None,
        fee_rate=intent.extra.get("fee_rate"),
        peer_count=intent.extra.get("peer_count"),
    )

    user = UserContext(
        user_id=intent.user_id,
        biometric_available=bool(intent.extra.get("biometric_available", False)),
        pin_set=bool(intent.extra.get("pin_set", False)),
    )

    return EQCContext(
        action=action, device=device, network=network, user=user, extra=dict(intent.extra)
    )


def execute_signing_intent(
    *,
    intent: SigningIntent,
    executor: Callable[[EQCContext], Any],
    eqc_engine: Optional[EQCEngine] = None,
    shield: Optional[ShieldEvaluator] = None,
    use_wsqk: bool = True,
    ttl_seconds: int = 120,
) -> Any:
    """Execute a signing-like operation under EQC + Shield + (optional) WSQK.

    Returns:
        The executor's result.

    Raises:
        ExecutionBlocked: if EQC denies or Shield blocks.
    """
    eqc = eqc_engine or EQCEngine()
    shield_eval = shield or DefaultShieldEvaluator()

    # 1) EQC must allow
    context = _build_eqc_context(intent)
    decision = eqc.decide(context)

    # Import VerdictType safely (tests rely on core.eqc.verdicts)
    try:
        from core.eqc.verdicts import VerdictType
    except Exception as e:  # pragma: no cover
        raise ExecutionBlocked(f"EQC verdict import failed: {e}") from e

    if decision.verdict != VerdictType.ALLOW:
        raise ExecutionBlocked(f"EQC blocked signing intent: {decision.verdict}")

    # 2) Shield must not block
    sdec = shield_eval.evaluate(intent)
    if getattr(sdec, "blocked", False):
        raise ExecutionBlocked(
            f"Shield blocked signing intent: {getattr(sdec, 'reason', '')}"
        )

    # 3) Execute (optionally under WSQK scope binding)
    if not use_wsqk:
        return executor(context)

    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id=intent.wallet_id,
        action=intent.action,
        ttl_seconds=ttl_seconds,
    )
    out = execute_with_scope(
        scope=bound.scope,
        context=context,
        wallet_id=intent.wallet_id,
        action=intent.action,
        executor=executor,
    )
    return out.result
