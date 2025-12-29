from core.wallet.keys.mnemonic import from_phrase, seed_from_mnemonic


def test_bip39_vector_abandon_trezor_seed():
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    m = from_phrase(phrase)
    assert len(m.words) == 12

    seed = seed_from_mnemonic(phrase, passphrase="TREZOR").hex()
    assert seed == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )
