"""
core.eqc — Public API surface (stable imports)

This module intentionally re-exports only the stable, documented types
used by the rest of Adamantine Wallet OS.

Do NOT import internal modules from outside core.eqc.* directly.
If you need something new, add it here deliberately.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

# Context / data types
from .context import EQCContext

# Decisions / verdicts
from .decision import EQCDecision
from .verdicts import VerdictType, ReasonCode

# Engine
from .engine import EQCEngine

__all__ = [
    "EQCEngine",
    "EQCContext",
    "EQCDecision",
    "VerdictType",
    "ReasonCode",
]
