"""
Wallet errors (scaffold)

TODO:
- Add specific exceptions for key management, signing, sync, storage
"""

class WalletError(Exception):
    """Base wallet exception."""


class NotImplementedYet(WalletError):
    """Raised for scaffold-only functions."""
