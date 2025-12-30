from core.runtime.shield_signing_gate import SigningIntent


def test_intent_hash_changes_when_intent_changes():
    a = SigningIntent(
        wallet_id="wallet-1",
        account_id="account-1",
        action="send",
        asset="DGB",
        to_address="DGB1-test",
        amount_minor=1,
    )
    b = SigningIntent(
        wallet_id="wallet-1",
        account_id="account-1",
        action="send",
        asset="DGB",
        to_address="DGB1-test",
        amount_minor=2,  # changed
    )

    assert a.intent_hash() != b.intent_hash()
