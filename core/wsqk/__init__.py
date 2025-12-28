"""
core.wsqk — Public API surface (stable imports)

WSQK is an execution authority model.
This __init__ file is the stable import boundary for WSQK types.

Author: DarekDGB
License: MIT (see root LICENSE)
"""

from __future__ import annotations

# Core types
from .scopes import WSQKScope
from .session import WSQKSession

# Public functions (binding + execution)
from .context_bind import bind_scope_from_eqc
from .executor import execute_with_scope

__all__ = [
    "WSQKScope",
    "WSQKSession",
    "bind_scope_from_eqc",
    "execute_with_scope",
]
