from core.wallet.keys.hd import HDNode, SECP256K1_N


def test_bip32_vector1_master_and_m0h():
    # BIP32 Test Vector 1 seed (hex)
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    master = HDNode.from_seed(seed)

    # Expected from BIP32 vector 1:
    assert master.private_key_hex == "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    assert master.chain_code_hex == "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"

    # m/0' (hardened)
    child = master.derive_hardened(0)

    # Expected from BIP32 vector 1 for m/0':
    assert child.private_key_hex == "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    assert child.chain_code_hex == "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"


def test_secp256k1_n_sanity():
    # simple sanity check: n is 256-bit-ish and > 0
    assert SECP256K1_N > 0
    assert SECP256K1_N.bit_length() >= 250
