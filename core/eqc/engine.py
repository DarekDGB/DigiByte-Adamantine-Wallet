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
    - any exact name in preferred_names
    - any class containing a token (Policy / Tx / Device / Classifier)
    - deterministic first by name
    """
    mod = importlib.import_module(module_path)

    candidates = []
    for name, obj in vars(mod).items():
        if inspect.isclass(obj) and obj.__module__ == mod.__name__ and hasattr(obj, required_method):
            candidates.append((name, obj))

    if not candidates:
        raise ImportError(f"No class with '{required_method}()' found in {module_path}.")

    by_name = {name: obj for name, obj in candidates}
    for pname in preferred_names:
        if pname in by_name:
            return by_name[pname]

    # Token preference
    tokens = []
    for tok in ("Policy", "Tx", "Device", "Classifier"):
        if any(tok in pname for pname in preferred_names):
            tokens.append(tok)

    for name, obj in sorted(candidates, key=lambda x: x[0]):
        if any(tok in name for tok in tokens):
            return obj

    return sorted(candidates, key=lambda x: x[0])[0][1]


def _call_policy_evaluate(policy_obj, *, context, device_signals, tx_signals):
    """
    Call policy.evaluate(...) in a way that matches the policy's real signature.

    Supports common patterns:
    - evaluate(context)
    - evaluate(context, device_signals, tx_signals)
    - evaluate(context, tx_signals, device_signals)
    - evaluate(context, signals=...)
    - evaluate(context, **kwargs) (filtered by signature)

    This prevents CI breakage when policy implementations evolve.
    """
    fn = getattr(policy_obj, "evaluate", None)
    if fn is None:
        raise TypeError("EQC policy object has no evaluate() method")

    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    accepts_var_kw = any(p.kind == p.VAR_KEYWORD for p in params)

    # Candidate kwargs (only used if the policy accepts them)
    candidate_kwargs = {
        "device_signals": device_signals,
        "tx_signals": tx_signals,
        "signals": {"device": device_signals, "tx": tx_signals},
        "context": context,  # for policies doing evaluate(context=...)
    }

    accepted = {}
    for p in params:
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            if p.name in candidate_kwargs:
                accepted[p.name] = candidate_kwargs[p.name]

    # 1) Try positional: evaluate(context, device_signals, tx_signals)
    try:
        return fn(context, device_signals, tx_signals)
    except TypeError:
        pass

    # 2) Try positional swapped: evaluate(context, tx_signals, device_signals)
    try:
        return fn(context, tx_signals, device_signals)
    except TypeError:
        pass

    # 3) Try kwargs (only those accepted / or if **kwargs exists)
    try:
        # avoid passing context twice
        accepted.pop("context", None)
        if accepts_var_kw or accepted:
            return fn(context, **accepted)
    except TypeError:
        pass

    # 4) Final fallback: evaluate(context) only
    return fn(context)


# Resolve implementations dynamically (avoids brittle naming)
_PolicyClass = _resolve_class(
    module_path="core.eqc.policy",
    preferred_names=["DefaultPolicy", "EQCPolicy", "Policy", "BasePolicy"],
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

    Supports optional policy packs (opt-in).
    If no packs are enabled, behavior remains unchanged.
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

        self._policy_registry = policy_registry or PolicyPackRegistry()
        self._enabled_policy_packs: List[str] = list(enabled_policy_packs or [])

    def decide(self, context: EQCContext) -> EQCDecision:
        # Classify
        device_signals = self._device.classify(context)
        tx_signals = self._tx.classify(context)

        # Base policy evaluation (signature-adaptive)
        base_verdict = _call_policy_evaluate(
            self._policy,
            context=context,
            device_signals=device_signals,
            tx_signals=tx_signals,
        )

        # Optional policy pack verdicts (opt-in)
        pack_verdicts: List[Verdict] = self._policy_registry.evaluate(
            context=context,
            enabled=self._enabled_policy_packs,
        )

        # Merge verdicts (DENY > STEP_UP > ALLOW)
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
