"""
Example EQC Policy Pack: High Value Step-Up

This pack demonstrates how deployments can enforce stricter confirmation
for high-value transfers without modifying the base EQC policy.

IMPORTANT DESIGN RULE:
Policy packs must only TIGHTEN security. (They should never loosen it.)

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from typing import Any, List, Optional

from core.eqc.context import EQCContext
from core.eqc.policies.types import PolicyPack
from core.eqc.verdicts import Verdict, VerdictType, StepUp, Reason, ReasonCode


class HighValueStepUpPack(PolicyPack):
    """
    Require STEP_UP for high-value sends.

    IMPORTANT:
    PolicyPack base class requires __init__(name, rules).
    The registry instantiates packs with obj() (no args),
    so this class MUST have a zero-arg constructor.
    """

    def __init__(
        self,
        threshold: int = 10_000,
        *,
        name: str = "HIGH_VALUE_STEP_UP",
        rules: Optional[List[Any]] = None,
    ):
        super().__init__(name=name, rules=list(rules or []))
        self.threshold = int(threshold)

    def evaluate(self, context: EQCContext) -> Verdict:
        a = context.action

        # Only apply to "send"
        if (a.action or "").lower() != "send":
            return Verdict.allow()

        if a.amount is None:
            return Verdict.allow()

        try:
            amount = int(a.amount)
        except Exception:
            return Verdict.allow()

        if amount < self.threshold:
            return Verdict.allow()

        step = StepUp(
            requirements=["confirm_user_intent"],
            message=f"High-value send requires confirmation (>= {self.threshold}).",
        )

        reason = Reason(
            code=ReasonCode.LARGE_AMOUNT,
            message=f"High-value transfer detected (amount={amount} >= threshold={self.threshold}).",
            details={"threshold": self.threshold, "amount": amount},
        )

        return Verdict(
            type=VerdictType.STEP_UP,
            reasons=[reason],
            step_up=step,
        )
