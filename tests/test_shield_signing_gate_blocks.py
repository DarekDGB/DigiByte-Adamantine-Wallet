from __future__ import annotations

import pytest

from core.runtime.shield_signing_gate import (
    SigningIntent,
    execute_signing_intent,
    ShieldEvaluator,
)
from core.runtime.orchestrator import ExecutionBlocked
from core.shield_bridge_client import ShieldDecision
from core.eqc.context import EQCContext


class BlockingShield(ShieldEvaluator):
    def evaluate(self, intent: SigningIntent) -> ShieldDecision:
        return ShieldDecision.block(reason="test_block", risk_score=99.0)


def test_shield_gate_blocks_before_executor_runs():
    ran = {"flag": False}

    def executor(ctx: EQCContext):
        ran["flag"] = True
        return "signed"

    intent = SigningIntent(
        wallet_id="w1",
        account_id="a1",
        action="sign",
        asset="DGB",
        amount=1,
        recipient="DGBTEST",
        device_type="mobile",
        platform="ios",
        network_type="wifi",
        user_id="u1",
    )

    with pytest.raises(ExecutionBlocked):
        execute_signing_intent(intent=intent, executor=executor, shield=BlockingShield())

    assert ran["flag"] is False
