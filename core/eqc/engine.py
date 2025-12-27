"""
EQC Engine — Equilibrium Confirmation

Deterministic decision engine for Adamantine Wallet OS.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict, VerdictType

# ✅ Compatibility: your policy module may not use "DefaultPolicy"
try:
    from core.eqc.policy import DefaultPolicy as _PolicyClass
except ImportError:  # pragma: no cover
    from core.eqc.policy import Policy as _PolicyClass

from core.eqc.classifiers.device_classifier import DeviceClassifier
from core.eqc.classifiers.tx_classifier import TxClassifier

from core.eqc.policies.registry import PolicyPackRegistry


@dataclass
class EQCDecision:
    context_hash: str
    verdict: Verdict
    signals: dict


class EQCEngine:
    """
    EQC decision brain.

    Supports optional policy packs (opt-in):
    - If no packs are enabled, behavior is unchanged.
    """

    def __init__(
        self,
        policy: Optional[_PolicyClass] = None,
        device_classifier: Optional[DeviceClassifier] = None,
        tx_classifier: Optional[TxClassifier] = None,
        policy_registry: Optional[PolicyPackRegistry] = None,
        enabled_policy_packs: Optional[Sequence[str]] = None,
    ):
        self._policy = policy or _PolicyClass()
        self._device = device_classifier or DeviceClassifier()
        self._tx = tx_classifier or TxClassifier()

        # Policy packs (opt-in)
        self._policy_registry = policy_registry or PolicyPackRegistry()
        self._enabled_policy_packs: List[str] = list(enabled_policy_packs or [])

    def decide(self, context: EQCContext) -> EQCDecision:
        # Classify
        device_signals = self._device.classify(context)
        tx_signals = self._tx.classify(context)

        # Base policy evaluation (existing behavior)
        base_verdict = self._policy.evaluate(context, device_signals=device_signals, tx_signals=tx_signals)

        # Optional policy pack verdicts
        pack_verdicts: List[Verdict] = self._policy_registry.evaluate(
            context=context,
            enabled=self._enabled_policy_packs,
        )

        # Merge: strongest verdict wins (DENY > STEP_UP > ALLOW)
        final_verdict = _merge_verdicts([base_verdict] + pack_verdicts)

        # Context hash
        ctx_hash = context.context_hash()

        signals = {
            "device": device_signals,
            "tx": tx_signals,
            "policy_packs": [v.type for v in pack_verdicts],
        }

        return EQCDecision(context_hash=ctx_hash, verdict=final_verdict, signals=signals)

    # Convenience methods for enabling packs without rebuilding engine
    def enable_policy_pack(self, name: str) -> None:
        if name not in self._enabled_policy_packs:
            self._enabled_policy_packs.append(name)

    def disable_policy_pack(self, name: str) -> None:
        self._enabled_policy_packs = [n for n in self._enabled_policy_packs if n != name]

    @property
    def policy_registry(self) -> PolicyPackRegistry:
        return self._policy_registry


def _merge_verdicts(verdicts: List[Verdict]) -> Verdict:
    """
    Merge verdicts deterministically.
    Strongest wins: DENY > STEP_UP > ALLOW.
    """
    if any(v.type == VerdictType.DENY for v in verdicts):
        return Verdict(type=VerdictType.DENY, reason="Denied by policy evaluation")
    if any(v.type == VerdictType.STEP_UP for v in verdicts):
        return Verdict(type=VerdictType.STEP_UP, reason="Step-up required by policy evaluation")
    return Verdict(type=VerdictType.ALLOW, reason="Allowed by policy evaluation")
