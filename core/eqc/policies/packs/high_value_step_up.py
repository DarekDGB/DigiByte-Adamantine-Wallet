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

from core.eqc.context import EQCContext
from core.eqc.policies.types import PolicyPack
from core.eqc.verdicts import Verdict, VerdictType, StepUp, Reason, ReasonCode


class HighValueStepUpPack(PolicyPack):
    """
    Require step-up for high-value sends.

    NOTE:
    We intentionally do NOT use @dataclass here to avoid dataclass field-order
    conflicts with the PolicyPack base class (which may define non-default fields
    like `rules`).
    """

    name = "HIGH_VALUE_STEP_UP"
    threshold = 10_000  # example: 10k units (DGB / DigiDollar minor units etc.)

    def evaluate(self, context: EQCContext) -> Verdict:
        a = context.action

        # Only apply to sends with a numeric amount
        if (a.action or "").lower() != "send":
            return Verdict.allow()

        if a.amount is None:
            return Verdict.allow()

        try:
            amount = int(a.amount)
        except Exception:
            return Verdict.allow()

        if amount < int(self.threshold):
            return Verdict.allow()

        # Tighten ALLOW -> STEP_UP
        step = StepUp(
            requirements=["confirm_user_intent"],
            message=f"High-value send requires confirmation (>= {self.threshold}).",
        )

        reason = Reason(
            code=ReasonCode.LARGE_AMOUNT,
            message=f"High-value transfer detected (amount={amount} >= threshold={self.threshold}).",
            details={"threshold": int(self.threshold), "amount": amount},
        )

        return Verdict(
            type=VerdictType.STEP_UP,
            reasons=[reason],
            step_up=step,
        )
