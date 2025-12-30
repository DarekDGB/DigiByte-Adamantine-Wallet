import pytest

from core.runtime.orchestrator import ExecutionBlocked
from core.runtime.shield_signing_gate import SigningIntent, execute_signing_intent
from core.shield_bridge_client import ShieldDecision


class AlwaysBlockShield:
    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        return ShieldDecision.block(reason="test_block")


class AlwaysAllowShield:
    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        return ShieldDecision.allow(reason="test_allow")


def test_shield_gate_blocks_execution_when_shield_blocks():
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

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=executor,
            shield=AlwaysBlockShield(),
            use_wsqk=True,
        )

    assert called["n"] == 0


def test_shield_gate_allows_execution_when_shield_allows():
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

    assert out == {"ok": True}
    assert called["n"] == 1
