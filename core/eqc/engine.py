"""
EQC Engine — Equilibrium Confirmation

Deterministic decision engine for Adamantine Wallet OS.

Core invariants enforced here:
- Browser contexts are denied (ReasonCode.BROWSER_CONTEXT_BLOCKED)
- Extension contexts are denied (ReasonCode.EXTENSION_CONTEXT_BLOCKED)
- DigiDollar mint/redeem requires step-up (with step_up.requirements)

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import inspect
import os
from typing import Any, Dict, List, Optional, Sequence, Type

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict, VerdictType
from core.eqc.policies.registry import PolicyPackRegistry


# --- Dynamic class resolution -------------------------------------------------


def _resolve_class(module_path: str, preferred_names: List[str], required_method: str) -> Type:
    """
    Resolve a class from a module without hardcoding its exact name.
    Selects a class that:
    - is defined in the target module
    - has `required_method`
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

    # deterministic fallback by name
    return sorted(candidates, key=lambda x: x[0])[0][1]


def _parse_policy_packs_env() -> List[str]:
    """
    Reads policy packs from env var:

      EQC_POLICY_PACKS="module:PackA,module:PackB"

    Returns list of refs (strings).
    """
    raw = os.getenv("EQC_POLICY_PACKS", "") or ""
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


# --- Reason + Verdict helpers (compatible with your Verdict model) -----------


def _safe_reason(message: str, details: Optional[dict] = None, code_override: Any = None):
    """
    Create a Reason object if the repo defines it.
    If code_override is provided and ReasonCode exists, we use it.
    """
    details = details or {}

    try:
        from core.eqc.verdicts import Reason, ReasonCode  # type: ignore

        if code_override is not None:
            return Reason(code=code_override, message=message, details=details)

        code = getattr(ReasonCode, "ENGINE_INVARIANT", None) or getattr(
            ReasonCode, "POLICY_RULE_MATCH", None
        )
        if code is not None:
            return Reason(code=code, message=message, details=details)

        return Reason(code="ENGINE_INVARIANT", message=message, details=details)  # type: ignore
    except Exception:
        return {"message": message, "details": details, "code": str(code_override) if code_override else None}


def _make_verdict(
    vtype: VerdictType,
    message: str,
    details: Optional[dict] = None,
    *,
    reason_code: Any = None,
) -> Verdict:
    """
    Construct Verdict using the repo's real constructor shape:
      Verdict(type=..., reasons=[...], step_up=...)
    """
    return Verdict(type=vtype, reasons=[_safe_reason(message, details, code_override=reason_code)])  # type: ignore[arg-type]


class _CompatStepUp:
    """Minimal StepUp object for tests: must expose .requirements (list)."""

    def __init__(self, requirements: List[Any]):
        self.requirements = requirements


def _attach_step_up(verdict: Verdict, requirements: List[Any]) -> Verdict:
    """
    IMPORTANT: Verdict is a frozen dataclass in this repo.
    Tests expect: decision.verdict.step_up.requirements
    So we must set the dataclass field using object.__setattr__.
    """
    step = _CompatStepUp(requirements=requirements)
    try:
        object.__setattr__(verdict, "step_up", step)
    except Exception:
        setattr(verdict, "step_up", step)
    return verdict


# --- Policy evaluate adapter --------------------------------------------------


def _call_policy_evaluate(policy_obj, *, context, device_signals, tx_signals):
    """
    Call policy.evaluate(...) matching the policy's real signature.
    """
    fn = getattr(policy_obj, "evaluate", None)
    if fn is None:
        raise TypeError("EQC policy object has no evaluate() method")

    # 1) Try kwargs (newer style)
    try:
        return fn(context, device_signals=device_signals, tx_signals=tx_signals)
    except TypeError:
        pass

    # 2) Try positional (context, device, tx)
    try:
        return fn(context, device_signals, tx_signals)
    except TypeError:
        pass

    # 3) Try context only
    return fn(context)


# --- Resolved implementation classes -----------------------------------------


_PolicyClass = _resolve_class(
    module_path="core.eqc.policy",
    preferred_names=["DefaultPolicy", "EQCPolicy", "Policy", "BasePolicy"],
    required_method="evaluate",
)

_DeviceClassifierClass = _resolve_class(
    module_path="core.eqc.classifiers.device_classifier",
    preferred_names=["DeviceClassifier", "DefaultDeviceClassifier"],
    required_method="classify",
)

_TxClassifierClass = _resolve_class(
    module_path="core.eqc.classifiers.tx_classifier",
    preferred_names=["TxClassifier", "TransactionClassifier", "DefaultTxClassifier"],
    required_method="classify",
)


# --- Public types -------------------------------------------------------------


@dataclass
class EQCDecision:
    context_hash: str
    verdict: Verdict
    signals: Dict[str, Any]


# --- Engine ------------------------------------------------------------------


class EQCEngine:
    """
    EQC decision brain.

    Enforces OS-level invariants first.
    Then classifies signals.
    Then evaluates base policy.
    Then evaluates optional policy packs.
    Then merges verdicts deterministically.
    """

    def __init__(
        self,
        policy: Optional[Any] = None,
        device_classifier: Optional[Any] = None,
        tx_classifier: Optional[Any] = None,
        policy_registry: Optional[PolicyPackRegistry] = None,
        enabled_policy_packs: Optional[Sequence[str]] = None,
    ):
        self._policy = policy or _PolicyClass()
        self._device = device_classifier or _DeviceClassifierClass()
        self._tx = tx_classifier or _TxClassifierClass()

        self._policy_registry = policy_registry or PolicyPackRegistry()

        # If enabled_policy_packs is not provided, read from EQC_POLICY_PACKS env var.
        if enabled_policy_packs is None:
            self._enabled_policy_packs = _parse_policy_packs_env()
        else:
            self._enabled_policy_packs = list(enabled_policy_packs)

    def decide(self, context: EQCContext) -> EQCDecision:
        # --- Hard invariants (must be true even if policies change) -----

        device_type = (getattr(context.device, "device_type", None) or "").lower()
        action_name = (getattr(context.action, "action", None) or "").lower()
        asset_name = (getattr(context.action, "asset", None) or "").lower()

        # Pull ReasonCode safely (tests check these exact codes)
        try:
            from core.eqc.verdicts import ReasonCode  # type: ignore
        except Exception:
            ReasonCode = None  # type: ignore

        # 1) Browser is structurally denied
        if device_type == "browser":
            code = getattr(ReasonCode, "BROWSER_CONTEXT_BLOCKED", None) if ReasonCode else None
            verdict = _make_verdict(
                VerdictType.DENY,
                "Execution denied: browser context is not permitted.",
                {"device_type": device_type},
                reason_code=code,
            )
            return EQCDecision(
                context_hash=context.context_hash(),
                verdict=verdict,
                signals={"invariant": "HOSTILE_RUNTIME", "device_type": device_type},
            )

        # 2) Extension is structurally denied
        if device_type == "extension":
            code = getattr(ReasonCode, "EXTENSION_CONTEXT_BLOCKED", None) if ReasonCode else None
            verdict = _make_verdict(
                VerdictType.DENY,
                "Execution denied: extension context is not permitted.",
                {"device_type": device_type},
                reason_code=code,
            )
            return EQCDecision(
                context_hash=context.context_hash(),
                verdict=verdict,
                signals={"invariant": "HOSTILE_RUNTIME", "device_type": device_type},
            )

        # 3) DigiDollar mint/redeem requires step-up (must provide requirements)
        if action_name in {"mint", "redeem"} and asset_name in {"digidollar", "dd"}:
            code = (
                getattr(ReasonCode, "MINT_REDEEM_REQUIRES_STEP_UP", None)
                if ReasonCode
                else None
            )
            verdict = _make_verdict(
                VerdictType.STEP_UP,
                "Step-up required: DigiDollar mint/redeem requires additional confirmation.",
                {"action": action_name, "asset": asset_name},
                reason_code=code,
            )
            verdict = _attach_step_up(verdict, requirements=["confirm_user_intent"])
            return EQCDecision(
                context_hash=context.context_hash(),
                verdict=verdict,
                signals={"invariant": "DD_STEP_UP", "action": action_name, "asset": asset_name},
            )

        # --- Classify ---------------------------------------------------

        device_signals = self._device.classify(context)
        tx_signals = self._tx.classify(context)

        # --- Base policy (adaptive call) --------------------------------

        base_verdict: Verdict = _call_policy_evaluate(
            self._policy,
            context=context,
            device_signals=device_signals,
            tx_signals=tx_signals,
        )

        # --- Optional policy packs (opt-in) -----------------------------

        pack_verdicts: List[Verdict] = self._policy_registry.evaluate(
            context=context,
            enabled=self._enabled_policy_packs,
            device_signals=device_signals,
            tx_signals=tx_signals,
        )

        # --- Merge verdicts ---------------------------------------------

        final_verdict = _merge_verdicts([base_verdict] + pack_verdicts)

        signals = {
            "device": device_signals,
            "tx": tx_signals,
            "policy_packs": [getattr(v, "type", None) for v in pack_verdicts],
        }

        return EQCDecision(
            context_hash=context.context_hash(),
            verdict=final_verdict,
            signals=signals,
        )

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
    Merge verdicts deterministically with correct Verdict structure.

    Priority:
      DENY > STEP_UP > ALLOW

    IMPORTANT:
    Preserve STEP_UP payload (verdict.step_up) when STEP_UP wins, otherwise
    tests may see the class staticmethod Verdict.step_up (a function) instead of
    the instance field step_up (an object with .requirements).
    """
    if not verdicts:
        return _make_verdict(VerdictType.DENY, "No verdicts produced by EQC.")

    def _reasons(v: Verdict) -> List[Any]:
        r = getattr(v, "reasons", None)
        return list(r) if r else []

    def _first_step_up(vs: List[Verdict]):
        for v in vs:
            su = getattr(v, "step_up", None)
            # Ignore callable (classmethod/staticmethod fallback)
            if su is not None and not callable(su):
                return su
        return None

    # DENY
    if any(v.type == VerdictType.DENY for v in verdicts):
        chosen = [v for v in verdicts if v.type == VerdictType.DENY]
        merged: List[Any] = []
        for v in chosen:
            merged.extend(_reasons(v))
        if not merged:
            merged = [_safe_reason("Denied by EQC policy evaluation.", {})]
        return Verdict(type=VerdictType.DENY, reasons=merged)  # type: ignore[arg-type]

    # STEP_UP
    if any(v.type == VerdictType.STEP_UP for v in verdicts):
        chosen = [v for v in verdicts if v.type == VerdictType.STEP_UP]
        merged: List[Any] = []
        for v in chosen:
            merged.extend(_reasons(v))
        if not merged:
            merged = [_safe_reason("Step-up required by EQC policy evaluation.", {})]

        step_up_obj = _first_step_up(chosen)
        return Verdict(type=VerdictType.STEP_UP, reasons=merged, step_up=step_up_obj)  # type: ignore[arg-type]

    # ALLOW
    chosen = [v for v in verdicts if v.type == VerdictType.ALLOW]
    if chosen:
        merged: List[Any] = []
        for v in chosen:
            merged.extend(_reasons(v))
        if not merged:
            merged = [_safe_reason("Allowed by EQC policy evaluation.", {})]
        return Verdict(type=VerdictType.ALLOW, reasons=merged)  # type: ignore[arg-type]

    return verdicts[0]
