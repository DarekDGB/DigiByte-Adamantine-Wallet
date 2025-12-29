from core.wallet.keys.hd import HDNode


def test_nonhardened_derivation_smoke_and_lengths():
    # BIP32 test seed (vector 1 seed)
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = HDNode.from_seed(seed)

    child0 = root.derive_nonhardened(0)

    # Basic correctness: fixed sizes
    assert len(bytes.fromhex(child0.private_key_hex)) == 32
    assert len(bytes.fromhex(child0.chain_code_hex)) == 32

    # Parent fingerprint should be 4 bytes (8 hex chars)
    assert len(bytes.fromhex(child0.parent_fingerprint_hex)) == 4

    # Different indices should produce different children
    child1 = root.derive_nonhardened(1)
    assert child0.private_key_hex != child1.private_key_hex
    assert child0.chain_code_hex != child1.chain_code_hex
