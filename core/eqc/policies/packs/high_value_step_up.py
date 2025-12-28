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

from dataclasses import dataclass

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict, StepUpRequirement
from core.eqc.policies.types import PolicyPack


@dataclass(frozen=True)
class HighValueStepUpPack(PolicyPack):
    """
    Require step-up for high-value sends.
    """

    name: str = "HIGH_VALUE_STEP_UP"
    threshold: int = 10_000  # example: 10k units (DGB / DigiDollar minor units etc.)

    def evaluate(self, context: EQCContext) -> Verdict:
        a = context.action

        # Only apply to sends with a numeric amount
        if a.action.lower() != "send":
            return Verdict.allow()

        if a.amount is None:
            return Verdict.allow()

        if int(a.amount) < int(self.threshold):
            return Verdict.allow()

        # Step-up requirements are intentionally minimal + generic for scaffolding.
        return Verdict.step_up(
            requirements=[
                StepUpRequirement(name="confirm_user_intent"),
            ],
            message=f"High-value send requires confirmation (>= {self.threshold}).",
            details={"threshold": self.threshold, "amount": a.amount},
        )
