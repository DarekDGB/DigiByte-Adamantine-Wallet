"""
core.runtime — Public API surface (stable imports)

IMPORTANT:
This package must remain lightweight to avoid circular imports.

Runtime Orchestrator enforces:
    EQC decides. WSQK executes. Runtime enforces.

To import orchestrator symbols, import them directly:
    from core.runtime.orchestrator import RuntimeOrchestrator, ExecutionBlocked

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

__all__ = []
