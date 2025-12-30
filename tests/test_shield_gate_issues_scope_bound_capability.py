from core.runtime.shield_signing_gate import SigningIntent, execute_signing_intent


class AlwaysAllowShield:
    def evaluate(self, intent):
        class _D:
            blocked = False
            reason = "ok"
        return _D()


def test_shield_gate_executes_with_wsqk_when_shield_allows():
    called = {"n": 0}

    def executor(_ctx):
        called["n"] += 1
        return {"ok": True}

    intent = SigningIntent(
        wallet_id="wallet-1",
        account_id="account-1",
        action="send",
        asset="DGB",
        to_address="DGB1-test",
        amount_minor=1,
    )

    out = execute_signing_intent(
        intent=intent,
        executor=executor,
        shield=AlwaysAllowShield(),
        use_wsqk=True,
    )

    assert called["n"] == 1
    assert out == {"ok": True}
