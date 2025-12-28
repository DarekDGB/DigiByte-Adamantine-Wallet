import os

from core.eqc.engine import EQCEngine
from core.eqc.context import EQCContext, ActionContext, DeviceContext, NetworkContext, UserContext
from core.eqc.policy import VerdictType


def _ctx(device_type="mobile", trusted=True, action="send", asset="DGB") -> EQCContext:
    return EQCContext(
        action=ActionContext(action=action, asset=asset, amount=1, recipient="DGB1-test"),
        device=DeviceContext(device_type=device_type, trusted=trusted, os="ios", app_version="0.1.0"),
        network=NetworkContext(node_type="local", node_trusted=True, entropy_score=0.9, peer_count=8),
        user=UserContext(user_id="user-1", biometric_available=True, pin_set=True),
        timestamp=1766877694,
        extra={},
    )


def test_policy_pack_cannot_override_base_deny(monkeypatch):
    """
    Base DENY must remain DENY even if a policy pack tries to ALLOW.
    """
    # Base policy DENY: browser is hostile invariant
    monkeypatch.setenv("EQC_POLICY_PACKS", "core.eqc.policies.packs.high_value_step_up:HighValueStepUpPack")

    engine = EQCEngine()
    decision = engine.decide(_ctx(device_type="browser", trusted=True))

    assert decision.verdict.type == VerdictType.DENY


def test_policy_pack_can_tighten_allow_into_step_up(monkeypatch):
    """
    Base ALLOW may be tightened into STEP_UP by a policy pack.
    """
    # Enable pack
    monkeypatch.setenv("EQC_POLICY_PACKS", "core.eqc.policies.packs.high_value_step_up:HighValueStepUpPack")

    engine = EQCEngine()
    # Choose a context that base policy ALLOWs (trusted mobile)
    ctx = _ctx(device_type="mobile", trusted=True, action="send", asset="DGB")
    # Force a "high value" amount so pack triggers
    ctx = EQCContext(
        action=ActionContext(action="send", asset="DGB", amount=10_000_000, recipient="DGB1-test"),
        device=ctx.device,
        network=ctx.network,
        user=ctx.user,
        timestamp=ctx.timestamp,
        extra=ctx.extra,
    )

    decision = engine.decide(ctx)
    assert decision.verdict.type == VerdictType.STEP_UP
    assert decision.verdict.step_up is not None
    assert len(decision.verdict.step_up.requirements) >= 1
