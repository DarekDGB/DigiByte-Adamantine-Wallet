"""
EQC Policy Pack Registry

Provides a lightweight registry for policy packs.
Packs are opt-in and can be composed without modifying EQC core logic.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict
from .types import PolicyPack


@dataclass
class PolicyPackRegistry:
    """
    Holds named policy packs and evaluates them deterministically.
    """
    _packs: Dict[str, PolicyPack] = field(default_factory=dict)

    def register(self, pack: PolicyPack) -> None:
        self._packs[pack.name] = pack

    def get(self, name: str) -> Optional[PolicyPack]:
        return self._packs.get(name)

    def list(self) -> List[str]:
        return sorted(self._packs.keys())

    def evaluate(self, context: EQCContext, enabled: Optional[Iterable[str]] = None) -> List[Verdict]:
        """
        Evaluate enabled packs in deterministic order.

        If enabled is None or empty, returns [] (opt-in by default).
        """
        if not enabled:
            return []

        verdicts: List[Verdict] = []
        for name in sorted(set(enabled)):
            pack = self._packs.get(name)
            if not pack:
                continue
            verdicts.extend(list(pack.evaluate(context)))
        return verdicts
