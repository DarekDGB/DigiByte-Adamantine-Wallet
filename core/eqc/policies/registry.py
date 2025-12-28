"""
EQC Policy Pack Registry

Stores and resolves optional EQC policy packs.

Policy packs are *additive* evaluators intended to TIGHTEN security:
they may convert ALLOW -> STEP_UP or DENY, but must never loosen a DENY.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Protocol
import importlib


@dataclass(frozen=True)
class PolicyPackResult:
    """
    A pack returns either:
    - a Verdict-like object (must have `.type` and `.reasons`)
    - or None (meaning: no opinion)
    """
    verdict: Any


class PolicyPackCallable(Protocol):
    def __call__(self, context: Any, *, device_signals: Any, tx_signals: Any) -> Any: ...


class PolicyPackObject(Protocol):
    def evaluate(self, context: Any, *, device_signals: Any, tx_signals: Any) -> Any: ...


PolicyPack = Any  # callable or object with .evaluate


def _resolve_pack_ref(ref: str) -> PolicyPack:
    """
    Resolve a pack reference like:
      - "pkg.module:PackClass"
      - "pkg.module:pack_instance"
      - "pkg.module.pack_callable"   (fallback)

    Returns:
      - an object with .evaluate(...) OR
      - a callable(context, device_signals=..., tx_signals=...)
    """
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("Empty policy pack reference")

    module_name: str
    attr_name: Optional[str] = None

    if ":" in ref:
        module_name, attr_name = ref.split(":", 1)
        module_name = module_name.strip()
        attr_name = (attr_name or "").strip() or None
    else:
        # fallback: last dot is attr
        if "." not in ref:
            raise ValueError(f"Invalid policy pack ref: {ref!r}")
        module_name, attr_name = ref.rsplit(".", 1)
        module_name = module_name.strip()
        attr_name = (attr_name or "").strip() or None

    mod = importlib.import_module(module_name)

    if attr_name is None:
        raise ValueError(f"Invalid policy pack ref (missing attribute): {ref!r}")

    obj = getattr(mod, attr_name, None)
    if obj is None:
        raise ImportError(f"Policy pack attribute not found: {ref!r}")

    # If it's a class, instantiate.
    if isinstance(obj, type):
        return obj()

    # Otherwise return the object/callable directly.
    return obj


class PolicyPackRegistry:
    """
    Registry mapping `name` -> pack object/callable.

    If `evaluate()` is called with `enabled` refs that are not registered,
    we will attempt to lazy-load them via importlib and register under the same ref.
    """

    def __init__(self) -> None:
        self._packs: Dict[str, PolicyPack] = {}

    def register_pack(self, name: str, pack: PolicyPack) -> None:
        name = (name or "").strip()
        if not name:
            raise ValueError("Policy pack name cannot be empty")
        self._packs[name] = pack

    def _ensure_loaded(self, ref: str) -> None:
        ref = (ref or "").strip()
        if not ref:
            return
        if ref in self._packs:
            return
        pack = _resolve_pack_ref(ref)
        self.register_pack(ref, pack)

    def evaluate(self, context: Any, *, enabled: List[str], device_signals: Any, tx_signals: Any) -> List[Any]:
        """
        Run all enabled packs and return a list of Verdict-like objects.
        """
        verdicts: List[Any] = []
        for ref in enabled or []:
            ref = (ref or "").strip()
            if not ref:
                continue

            self._ensure_loaded(ref)
            pack = self._packs.get(ref)
            if pack is None:
                continue

            # object with evaluate(...)
            if hasattr(pack, "evaluate") and callable(getattr(pack, "evaluate")):
                out = pack.evaluate(context, device_signals=device_signals, tx_signals=tx_signals)
            else:
                # callable pack(...)
                out = pack(context, device_signals=device_signals, tx_signals=tx_signals)

            if out is not None:
                verdicts.append(out)

        return verdicts
