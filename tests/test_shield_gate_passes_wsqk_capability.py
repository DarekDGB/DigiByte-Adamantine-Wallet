from core.runtime.shield_signing_gate import SigningIntent, execute_signing_intent


def test_shield_gate_executes_when_eqc_allows_and_shield_allows():
    called = {"n": 0}

    def executor(_ctx):
        called["n"] += 1
        return {"ok": True}

    intent = SigningIntent(
        wallet_id="wallet-1",
        account_id="account-1",
        action="sign",
        asset="DGB",
    )

    out = execute_signing_intent(intent=intent, executor=executor, use_wsqk=False)
    assert out == {"ok": True}
    assert called["n"] == 1
