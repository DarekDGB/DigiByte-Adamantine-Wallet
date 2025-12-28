"""
EQC Verdicts — Equilibrium Confirmation

This module defines the formal verdict and reasoning model used by
EQC (Equilibrium Confirmation).

Verdicts represent the final decision of EQC and are the ONLY
authorization signal for privileged actions inside Adamantine Wallet OS.

Core rule:
- If VerdictType is not ALLOW, no execution may occur.
- WSQK may only be invoked after VerdictType.ALLOW.

This module contains no execution logic and no cryptographic material.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, NewType


# Policy-pack compatibility: some packs import this from core.eqc.verdicts
# Keep it as a simple typed string so it works everywhere.
StepUpRequirement = NewType("StepUpRequirement", str)


class VerdictType(str, Enum):
    """
    High-level gate result.

    - ALLOW: operation may proceed (and only then can WSQK be invoked)
    - DENY: operation must not proceed
    - STEP_UP: operation requires additional assurances (e.g., re-auth, delay, 2nd factor)
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"


class ReasonCode(str, Enum):
    """
    Stable reason identifiers for audit logs, UI, and tests.
    Keep these short, explicit, and backwards-compatible.
    """

    # Generic / framework
    POLICY_RULE_MATCH = "POLICY_RULE_MATCH"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    INVALID_CONTEXT = "INVALID_CONTEXT"

    # Risk signals
    HIGH_RISK_SCORE = "HIGH_RISK_SCORE"
    NEW_DEVICE = "NEW_DEVICE"
    NEW_RECIPIENT = "NEW_RECIPIENT"
    LARGE_AMOUNT = "LARGE_AMOUNT"
    UNUSUAL_FEE = "UNUSUAL_FEE"
    RAPID_SUCCESSIVE_ACTIONS = "RAPID_SUCCESSIVE_ACTIONS"
    GEO_ANOMALY = "GEO_ANOMALY"
    TIME_ANOMALY = "TIME_ANOMALY"

    # Architecture enforcement (non-negotiable)
    BROWSER_CONTEXT_BLOCKED = "BROWSER_CONTEXT_BLOCKED"
    EXTENSION_CONTEXT_BLOCKED = "EXTENSION_CONTEXT_BLOCKED"
    SEED_EXPOSURE_RISK = "SEED_EXPOSURE_RISK"

    # Asset / protocol
    MINT_REDEEM_REQUIRES_STEP_UP = "MINT_REDEEM_REQUIRES_STEP_UP"
    POLICY_DISALLOWS_ACTION = "POLICY_DISALLOWS_ACTION"


@dataclass(frozen=True)
class Reason:
    """
    A single human + machine readable explanation for the verdict.
    """

    code: ReasonCode
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": dict(self.details) if self.details else {},
        }


@dataclass(frozen=True)
class StepUp:
    """
    Additional requirements needed before an operation can proceed.

    Examples:
    - "biometric": require FaceID/TouchID
    - "pin": require local PIN
    - "delay": enforce a time lock
    - "2of2": require a second device approval
    """

    requirements: List[str] = field(default_factory=list)
    message: str = "Additional verification required."

    def to_dict(self) -> Dict[str, Any]:
        return {"requirements": list(self.requirements), "message": self.message}


@dataclass(frozen=True)
class Verdict:
    """
    Final EQC output.

    NOTE: WSQK must ONLY be reachable from an orchestrator that checks:
      verdict.type == VerdictType.ALLOW
    """

    type: VerdictType
    reasons: List[Reason] = field(default_factory=list)
    step_up: Optional[StepUp] = None

    def is_allow(self) -> bool:
        return self.type == VerdictType.ALLOW

    def is_deny(self) -> bool:
        return self.type == VerdictType.DENY

    def is_step_up(self) -> bool:
        return self.type == VerdictType.STEP_UP

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "reasons": [r.to_dict() for r in self.reasons],
            "step_up": self.step_up.to_dict() if self.step_up else None,
        }

    # Convenience constructors
    @staticmethod
    def allow(*reasons: Reason) -> "Verdict":
        return Verdict(type=VerdictType.ALLOW, reasons=list(reasons))

    @staticmethod
    def deny(*reasons: Reason) -> "Verdict":
        return Verdict(type=VerdictType.DENY, reasons=list(reasons))

    @staticmethod
    def step_up(step_up: StepUp, *reasons: Reason) -> "Verdict":
        return Verdict(type=VerdictType.STEP_UP, reasons=list(reasons), step_up=step_up)
