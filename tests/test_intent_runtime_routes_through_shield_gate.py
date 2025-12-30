from __future__ import annotations

import pytest

from core.runtime.intent_runtime import WalletIntent, execute_intent
from core.runtime.orchestrator import ExecutionBlocked
from core.runtime.shield_signing_gate import ShieldEvaluator, SigningIntent
from core.shield_bridge_client import ShieldDecision
from core.eqc.context import EQCContext


class BlockingShield(ShieldEvaluator):
    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        return ShieldDecision.block(reason="intent_runtime_block", risk_score=99.0)


def test_execute_intent_routes_signing_like_actions_through_shield_gate():
    ran = {"flag": False}

    def executor(ctx: EQCContext):
        ran["flag"] = True
        return "ok"

    intent = WalletIntent(
        wallet_id="w1",
        account_id="a1",
        action="sign",
        asset="DGB",
        user_id="u1",
        device_type="mobile",
        platform="ios",
        network_type="wifi",
    )

    with pytest.raises(ExecutionBlocked):
        execute_intent(intent=intent, executor=executor, shield=BlockingShield())

    assert ran["flag"] is False


def test_execute_intent_validates_send_fields():
    def executor(ctx: EQCContext):
        return "ok"

    intent = WalletIntent(
        wallet_id="w1",
        account_id="a1",
        action="send",
        asset="DGB",
        # missing to_address + amount_minor on purpose
    )

    with pytest.raises(ValueError):
        execute_intent(intent=intent, executor=executor)
