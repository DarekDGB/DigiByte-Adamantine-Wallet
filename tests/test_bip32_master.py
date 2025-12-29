from core.wallet.keys.mnemonic import seed_from_mnemonic
from core.wallet.keys.hd import master_key_from_seed, HDNode


def test_bip32_master_from_bip39_seed_vector():
    # Standard BIP39 test vector mnemonic + passphrase
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = seed_from_mnemonic(phrase, passphrase="TREZOR")
    assert len(seed) == 64

    priv, cc = master_key_from_seed(seed)
    assert len(priv) == 32
    assert len(cc) == 32

    # Deterministic: calling again must match
    priv2, cc2 = master_key_from_seed(seed)
    assert priv == priv2
    assert cc == cc2


def test_hdnode_from_seed_smoke():
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = seed_from_mnemonic(phrase, passphrase="TREZOR")

    node = HDNode.from_seed(seed)
    assert node.depth == 0
    assert node.child_number == 0
    assert len(bytes.fromhex(node.private_key_hex)) == 32
    assert len(bytes.fromhex(node.chain_code_hex)) == 32
