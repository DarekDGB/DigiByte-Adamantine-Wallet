"""
core.eqc — Public API surface (stable imports)

This module intentionally re-exports only the stable, documented types
used by the rest of Adamantine Wallet OS.

If something moves internally, we keep compatibility here.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

# Context / data types
from .context import EQCContext

# Verdicts + reason codes (these files exist in your repo)
from .verdicts import VerdictType, ReasonCode

# Engine (always exists)
from .engine import EQCEngine

# EQCDecision location varies across refactors — resolve safely.
try:
    # If you ever add decision.py later
    from .decision import EQCDecision  # type: ignore
except ModuleNotFoundError:
    try:
        # Common pattern: decision dataclass defined in engine.py
        from .engine import EQCDecision  # type: ignore
    except Exception:
        # Fallback: some builds keep it in context.py
        from .context import EQCDecision  # type: ignore


__all__ = [
    "EQCEngine",
    "EQCContext",
    "EQCDecision",
    "VerdictType",
    "ReasonCode",
]
