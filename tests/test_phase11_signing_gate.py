import pytest

from core.runtime.shield_signing_gate import (
    SigningIntent,
    execute_signing_intent,
)
from core.runtime.orchestrator import ExecutionBlocked


class DummyVerdict:
    def __init__(self, verdict_type):
        self.type = verdict_type


class DummyDecision:
    def __init__(self, verdict_type):
        self.verdict = DummyVerdict(verdict_type)


def make_intent():
    return SigningIntent(
        wallet_id="wallet-1",
        account_id="account-1",
        action="send",
        asset="DGB",
        to_address="DGB_TEST_ADDR",
        amount_minor=1000,
    )


def test_watch_only_blocks_signing(monkeypatch):
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return True

    class DummyEQC:
        def decide(self, context):
            return DummyDecision("ALLOW")

    def dummy_executor(context):
        wsqk_called["count"] += 1
        return {"signed": True}

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=dummy_executor,
            eqc_engine=DummyEQC(),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0


def test_eqc_blocks_before_signing():
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return False

    class DummyEQC:
        def decide(self, context):
            return DummyDecision("DENY")

    def dummy_executor(context):
        wsqk_called["count"] += 1
        return {"signed": True}

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=dummy_executor,
            eqc_engine=DummyEQC(),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0


def test_shield_blocks_before_wsqk(monkeypatch):
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return False

    class DummyEQC:
        def decide(self, context):
            return DummyDecision("ALLOW")

    class DummyShield:
        def evaluate(self, intent):
            class R:
                blocked = True
                reason = "test block"
            return R()

    def dummy_executor(context):
        wsqk_called["count"] += 1
        return {"signed": True}

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=dummy_executor,
            eqc_engine=DummyEQC(),
            shield=DummyShield(),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0
