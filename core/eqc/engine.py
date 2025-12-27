"""
EQC Engine — Equilibrium Confirmation

Deterministic decision engine for Adamantine Wallet OS.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import inspect
from typing import List, Optional, Sequence, Type

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict, VerdictType

from core.eqc.policies.registry import PolicyPackRegistry


def _resolve_class(module_path: str, preferred_names: List[str], required_method: str) -> Type:
    """
    Resolve a class from a module without hardcoding its name.

    Selects a class that:
    - is defined in the target module
    - has `required_method`

    Preference order:
    - any name in preferred_names (if present)
    - any class containing the preferred token (e.g. "Policy", "Tx", "Device")
    - deterministic first by name
    """
    mod = importlib.import_module(module_path)

    candidates = []
    for name, obj in vars(mod).items():
        if inspect.isclass(obj) and obj.__module__ == mod.__name__ and hasattr(obj, required_method):
            candidates.append((name, obj))

    if not candidates:
        raise ImportError(
            f"No class with '{required_method}()' found in {module_path}."
        )

    by_name = {name: obj for name, obj in candidates}
    for pname in preferred_names:
        if pname in by_name:
            return by_name[pname]

    # If no exact preferred match, try token preference
    tokens = []
    for pname in preferred_names:
        for tok in ["Policy", "Tx", "Device", "Classifier"]:
            if tok in pname and tok not in tokens:
                tokens.append(tok)

    for name, obj in sorted(candidates, key=lambda x: x[0]):
        if any(tok in name for tok in tokens):
            return obj

    return sorted(candidates, key=lambda x: x[0])[0][1]


# Resolve implementations dynamically (no hardcoded naming)
_PolicyClass = _resolve_class(
    module_path="core.eqc.policy",
    preferred_names=["DefaultPolicy", "Policy", "EQCPolicy", "BasePolicy"],
    required_method="evaluate",
)

_DeviceClassifierClass = _resolve_class(
    module_path="core.eqc.classifiers.device_classifier",
    preferred_names=["DeviceClassifier", "DefaultDeviceClassifier", "DeviceSignalsClassifier"],
    required_method="classify",
)

_TxClassifierClass = _resolve_class(
    module_path="core.eqc.classifiers.tx_classifier",
    preferred_names=["TxClassifier", "TransactionClassifier", "TxSignalsClassifier", "DefaultTxClassifier"],
    required_method="classify",
)


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
        device_classifier: Optional[_DeviceClassifierClass] = None,
        tx_classifier: Optional[_TxClassifierClass] = None,
        policy_registry: Optional[PolicyPackRegistry] = None,
        enabled_policy_packs: Optional[Sequence[str]] = None,
    ):
        self._policy = policy or _PolicyClass()
        self._device = device_classifier or _DeviceClassifierClass()
        self._tx = tx_classifier or _TxClassifierClass()

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
