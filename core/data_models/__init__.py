"""
Core data models for Adamantine Wallet OS.

This package defines canonical, immutable data structures
used across the Wallet OS core and modules.
"""

from .wallet_state import WalletState

__all__ = [
    "WalletState",
]
