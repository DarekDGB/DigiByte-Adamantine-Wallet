"""
EQC Policy Pack Types

Defines the minimal interfaces for EQC policy packs.
Policy packs are deterministic rule collections evaluated by EQC.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, runtime_checkable

from core.eqc.context import EQCContext
from core.eqc.verdicts import Verdict


@runtime_checkable
class PolicyRule(Protocol):
    """
    A single deterministic policy rule.

    A rule must be:
    - pure (no side effects)
    - deterministic
    - context-only (no I/O)
    """

    name: str

    def evaluate(self, context: EQCContext) -> Verdict:
        ...


@dataclass(frozen=True)
class PolicyPack:
    """
    A collection of policy rules evaluated together.

    Policy packs are opt-in and composable.
    EQC core remains unchanged when new packs are added.
    """

    name: str
    rules: Iterable[PolicyRule]

    def evaluate(self, context: EQCContext) -> Iterable[Verdict]:
        """
        Evaluate all rules in this pack against the given context.
        """
        for rule in self.rules:
            yield rule.evaluate(context)
