"""
Import-only tests to keep CI green.

TODO:
- Add real unit tests once BIP39/HD/signing are implemented.
"""

def test_wallet_core_imports():
    from core.wallet.models import Network, Address  # noqa: F401
    from core.wallet.keys.mnemonic import from_phrase  # noqa: F401


def test_mnemonic_basic_parse():
    from core.wallet.keys.mnemonic import from_phrase
    m = from_phrase("abandon " * 11 + "about")
    assert len(m.words) == 12
