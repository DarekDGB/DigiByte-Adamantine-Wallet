import pytest

from core.wallet.keys.hd import HDNode  # derivation-capable private node
from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.public_derive import derive_child_public, PublicDerivationError
from core.wallet.keys.secp256k1 import pubkey_from_privkey


def test_public_derivation_matches_private_nonhardened() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root_priv = HDNode.from_seed(seed)

    # Build watch-only root from private root
    root_pub = PublicHDNode(
        chain_code=root_priv.chain_code,
        public_key=pubkey_from_privkey(root_priv.private_key, compressed=True),  # type: ignore[arg-type]
        depth=root_priv.depth,
        child_num=root_priv.child_num,
        parent_fingerprint=root_priv.parent_fingerprint,
        path=root_priv.path,
    )

    # Derive non-hardened child 0 in both worlds
    child_priv = root_priv.derive_nonhardened(0)
    child_pub = derive_child_public(root_pub, 0)

    expected_pub = pubkey_from_privkey(child_priv.private_key, compressed=True)  # type: ignore[arg-type]
    assert child_pub.public_key == expected_pub


def test_public_derivation_hardened_raises() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root_priv = HDNode.from_seed(seed)
    root_pub = PublicHDNode(
        chain_code=root_priv.chain_code,
        public_key=pubkey_from_privkey(root_priv.private_key, compressed=True),  # type: ignore[arg-type]
    )

    with pytest.raises(PublicDerivationError):
        derive_child_public(root_pub, 0x80000000)
