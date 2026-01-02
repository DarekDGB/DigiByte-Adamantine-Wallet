import pytest

from core.runtime.shield_signing_gate import (
    SigningIntent,
    execute_signing_intent,
)
from core.runtime.orchestrator import ExecutionBlocked

from core.storage.memory_store import MemoryWalletStorage
from core.wallet.account_store import AccountStore, AccountState


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


class DummyEQC:
    def __init__(self, verdict_type: str):
        self._verdict_type = verdict_type

    def decide(self, context):
        return DummyDecision(self._verdict_type)


def test_watch_only_blocks_via_account_store():
    """
    Proves persisted watch-only accounts block signing
    before EQC / Shield / WSQK.
    """
    storage = MemoryWalletStorage()
    account_store = AccountStore(storage)

    # Persist watch-only account
    account_store.save(
        AccountState(
            wallet_id="wallet-1",
            account_id="account-1",
            index=0,
            watch_only=True,
        )
    )

    intent = make_intent()

    with pytest.raises(ExecutionBlocked) as e:
        execute_signing_intent(
            intent=intent,
            executor=lambda ctx: {"ok": True},
            eqc_engine=DummyEQC("ALLOW"),
            account_store=account_store,
            use_wsqk=False,  # keep test minimal
        )

    assert "watch-only" in str(e.value)


def test_watch_only_blocks_signing_via_override_callable():
    """
    Proves the injected watch-only callable still blocks (override path).
    """
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return True

    def dummy_executor(context):
        wsqk_called["count"] += 1
        return {"signed": True}

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=dummy_executor,
            eqc_engine=DummyEQC("ALLOW"),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0


def test_eqc_blocks_before_signing():
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return False

    def dummy_executor(context):
        wsqk_called["count"] += 1
        return {"signed": True}

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(
            intent=intent,
            executor=dummy_executor,
            eqc_engine=DummyEQC("DENY"),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0


def test_shield_blocks_before_wsqk():
    intent = make_intent()
    wsqk_called = {"count": 0}

    def is_watch_only(wallet_id, account_id):
        return False

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
            eqc_engine=DummyEQC("ALLOW"),
            shield=DummyShield(),
            is_watch_only=is_watch_only,
        )

    assert wsqk_called["count"] == 0
