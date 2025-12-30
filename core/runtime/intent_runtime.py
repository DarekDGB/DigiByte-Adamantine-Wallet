"""
Canonical Intent Runtime — Adamantine Wallet OS

This module provides ONE obvious entry point for executing wallet intents.

Design goal:
    Intent -> EQC -> Shield -> WSQK -> Executor

This makes Shield + EQC unavoidable at the runtime boundary.

Author: DarekDGB
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from core.eqc.context import EQCContext
from core.runtime.orchestrator import ExecutionBlocked
from core.runtime.shield_signing_gate import (
    SigningIntent,
    ShieldEvaluator,
    execute_signing_intent,
)


@dataclass(frozen=True)
class WalletIntent:
    """High-level runtime intent used by clients and internal modules.

    This is intentionally simple and maps to SigningIntent where relevant.
    No secrets. Safe to log/audit.
    """

    wallet_id: str
    account_id: str

    # Common actions
    action: str  # e.g. "sign", "send", "transfer", "mint", "message_sign"
    asset: str = "DGB"

    # Optional tx-ish fields
    to_address: Optional[str] = None
    amount_minor: Optional[int] = None

    # Optional metadata for EQC/Shield context
    user_id: str = "user"
    device_type: str = "mobile"
    platform: str = "ios"
    network_type: str = "unknown"
    extra: Dict[str, Any] = field(default_factory=dict)


def _to_signing_intent(intent: WalletIntent) -> SigningIntent:
    """Map WalletIntent -> SigningIntent for signing-like operations."""
    return SigningIntent(
        wallet_id=intent.wallet_id,
        account_id=intent.account_id,
        action=intent.action,
        asset=intent.asset,
        to_address=intent.to_address,
        amount_minor=intent.amount_minor,
        user_id=intent.user_id,
        device_type=intent.device_type,
        platform=intent.platform,
        network_type=intent.network_type,
        extra=dict(intent.extra),
    )


def execute_intent(
    *,
    intent: WalletIntent,
    executor: Callable[[EQCContext], Any],
    shield: Optional[ShieldEvaluator] = None,
    use_wsqk: bool = True,
) -> Any:
    """Canonical runtime entry point.

    For signing-like actions, this ALWAYS routes through Shield signing gate.

    Args:
        intent: WalletIntent describing requested action.
        executor: callable that performs the action (runs only after gates pass).
        shield: optional Shield evaluator override.
        use_wsqk: execute under WSQK scope binding if True.

    Returns:
        executor result

    Raises:
        ExecutionBlocked: if EQC denies or Shield blocks.
        ValueError: if intent is malformed.
    """
    if not intent.wallet_id or not intent.account_id:
        raise ValueError("wallet_id and account_id are required")

    action = intent.action.strip().lower()

    # Signing-like operations MUST go through the signing gate
    signing_like = {
        "sign",
        "send",
        "transfer",
        "mint",
        "message_sign",
    }

    if action in signing_like:
        s_intent = _to_signing_intent(intent)

        # Basic validation for send/transfer patterns
        if action in {"send", "transfer"}:
            if not s_intent.to_address or s_intent.amount_minor is None:
                raise ValueError("send/transfer requires to_address and amount_minor")

        return execute_signing_intent(
            intent=s_intent,
            executor=executor,
            shield=shield,
            use_wsqk=use_wsqk,
        )

    # Non-signing operations can be routed later (sync, discovery, etc.)
    raise ExecutionBlocked(f"Unsupported or non-executable intent action: {intent.action}")
