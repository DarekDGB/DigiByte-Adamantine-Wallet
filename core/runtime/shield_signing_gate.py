"""
Shield Signing Gate — Adamantine Wallet OS

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional
import hashlib
import json

from core.eqc import EQCEngine
from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.runtime.orchestrator import ExecutionBlocked
from core.runtime.capabilities import issue_runtime_capability
from core.wsqk.context_bind import bind_scope_from_eqc
from core.wsqk.executor import execute_with_scope
from core.shield_bridge_client import ShieldBridgeClient, ShieldDecision

# NEW: persisted account source (optional)
from core.wallet.account_store import AccountStore


@dataclass(frozen=True)
class SigningIntent:
    wallet_id: str
    account_id: str
    action: str = "sign"
    asset: str = "DGB"
    amount: Optional[int] = None
    recipient: Optional[str] = None
    to_address: Optional[str] = None
    amount_minor: Optional[int] = None

    device_type: str = "mobile"
    platform: str = "ios"
    network_type: str = "unknown"
    user_id: str = "user"
    extra: Dict[str, Any] = field(default_factory=dict)

    def intent_hash(self) -> str:
        """Deterministic hash of the intent for audit + binding across layers."""
        payload = {
            "wallet_id": self.wallet_id,
            "account_id": self.account_id,
            "action": self.action,
            "asset": self.asset,
            "amount": self.amount,
            "recipient": self.recipient,
            "to_address": self.to_address,
            "amount_minor": self.amount_minor,
            "device_type": self.device_type,
            "platform": self.platform,
            "network_type": self.network_type,
            "user_id": self.user_id,
            "extra": dict(self.extra),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ShieldEvaluator:
    def evaluate(self, intent: SigningIntent) -> ShieldDecision:  # pragma: no cover
        raise NotImplementedError


class DefaultShieldEvaluator(ShieldEvaluator):
    def __init__(self, client: Optional[ShieldBridgeClient] = None) -> None:
        self._client = client or ShieldBridgeClient()

    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        ih = intent.intent_hash()

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
                meta={
                    "source": "shield_signing_gate",
                    "intent_hash": ih,
                },
            )

        return ShieldDecision.allow(reason=f"shield_gate_default_allow:{ih}")


def _build_eqc_context(intent: SigningIntent) -> EQCContext:
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

    extra = dict(intent.extra)
    extra["intent_hash"] = intent.intent_hash()

    return EQCContext(action=action, device=device, network=network, user=user, extra=extra)


def execute_signing_intent(
    *,
    intent: SigningIntent,
    executor: Callable[[EQCContext], Any],
    eqc_engine: Optional[EQCEngine] = None,
    shield: Optional[ShieldEvaluator] = None,
    # NEW: real persisted account source (optional)
    account_store: Optional[AccountStore] = None,
    # Still allowed: injected override for tests / custom policy
    is_watch_only: Optional[Callable[[str, str], bool]] = None,
    use_wsqk: bool = True,
    ttl_seconds: int = 120,
) -> Any:
    """
    THE signing gate entrypoint.

    Enforced order:
      0) Watch-only block (fast fail)
      1) EQC must ALLOW
      2) Shield must ALLOW
      3) WSQK executes (if enabled) otherwise executor runs directly
    """
    # 0) Watch-only hard block (override first, then persisted data)
    if is_watch_only is not None:
        if is_watch_only(intent.wallet_id, intent.account_id):
            raise ExecutionBlocked("watch-only account: signing is not permitted")
    elif account_store is not None:
        if account_store.is_watch_only(intent.wallet_id, intent.account_id):
            raise ExecutionBlocked("watch-only account: signing is not permitted")

    eqc = eqc_engine or EQCEngine()
    shield_eval = shield or DefaultShieldEvaluator()

    context = _build_eqc_context(intent)
    decision = eqc.decide(context)

    try:
        from core.eqc.verdicts import VerdictType
    except Exception as e:  # pragma: no cover
        raise ExecutionBlocked(f"EQC verdict import failed: {e}") from e

    if decision.verdict.type != VerdictType.ALLOW:
        raise ExecutionBlocked(f"EQC blocked signing intent: {decision.verdict.type}")

    sdec = shield_eval.evaluate(intent)
    if getattr(sdec, "blocked", False):
        raise ExecutionBlocked(f"Shield blocked signing intent: {getattr(sdec, 'reason', '')}")

    if not use_wsqk:
        return executor(context)

    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id=intent.wallet_id,
        action=intent.action,
        ttl_seconds=ttl_seconds,
    )

    cap = issue_runtime_capability(
        scope_hash=bound.scope.scope_hash(),
        ttl_seconds=ttl_seconds,
    )

    out = execute_with_scope(
        scope=bound.scope,
        context=context,
        wallet_id=intent.wallet_id,
        action=intent.action,
        executor=executor,
        capability=cap,
    )
    return out.result


# Phase 11 lock: make the "one public door" obvious to outsiders.
__all__ = ["SigningIntent", "execute_signing_intent"]
