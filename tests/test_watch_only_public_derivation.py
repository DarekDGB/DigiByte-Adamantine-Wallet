import pytest

from core.wallet.keys.hd import HDNode  # derivation-capable private node (hex fields)
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.public_derive import derive_child_public, PublicDerivationError
from core.wallet.keys.secp256k1 import pubkey_from_privkey


def _hex_to_bytes(h: str, expected_len: int) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
    return b


def test_public_derivation_matches_private_nonhardened() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root_priv = HDNode.from_seed(seed)

    # Adapt HDNode (hex fields) -> watch-only root
    chain_code = _hex_to_bytes(root_priv.chain_code_hex, 32)
    privkey = _hex_to_bytes(root_priv.private_key_hex, 32)

    root_pub = PublicHDNode(
        chain_code=chain_code,
        public_key=pubkey_from_privkey(privkey, compressed=True),
        depth=root_priv.depth,
        child_num=root_priv.child_number,
        parent_fingerprint=_hex_to_bytes(root_priv.parent_fingerprint_hex, 4),
        path=getattr(root_priv, "path", "m"),
    )

    # Derive non-hardened child 0 in both worlds
    child_priv = root_priv.derive_nonhardened(0)
    child_pub = derive_child_public(root_pub, 0)

    child_privkey = _hex_to_bytes(child_priv.private_key_hex, 32)
    expected_pub = pubkey_from_privkey(child_privkey, compressed=True)
    assert child_pub.public_key == expected_pub


def test_public_derivation_hardened_raises() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root_priv = HDNode.from_seed(seed)

    chain_code = _hex_to_bytes(root_priv.chain_code_hex, 32)
    privkey = _hex_to_bytes(root_priv.private_key_hex, 32)

    root_pub = PublicHDNode(
        chain_code=chain_code,
        public_key=pubkey_from_privkey(privkey, compressed=True),
    )

    with pytest.raises(PublicDerivationError):
        derive_child_public(root_pub, 0x80000000)
