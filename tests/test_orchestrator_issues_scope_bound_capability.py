from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.runtime.orchestrator import RuntimeOrchestrator


def _ctx() -> EQCContext:
    return EQCContext(
        action=ActionContext(action="send", asset="DGB", amount=1000, recipient="DGB1-test"),
        device=DeviceContext(
            device_id="device-1",
            device_type="mobile",
            os="ios",
            trusted=True,
            first_seen_ts=1700000000,
        ),
        network=NetworkContext(network="testnet", fee_rate=10, peer_count=8),
        user=UserContext(user_id="user-1", biometric_available=True, pin_set=True),
        extra={},
    )


def test_orchestrator_wsqk_path_executes():
    orch = RuntimeOrchestrator()
    called = {"n": 0}

    def executor(_context):
        called["n"] += 1
        return {"ok": True}

    out = orch.execute(
        context=_ctx(),
        executor=executor,
        use_wsqk=True,
        wallet_id="wallet-1",
        action="send",
        ttl_seconds=60,
    )

    assert called["n"] == 1
    assert out.result == {"ok": True}
    assert isinstance(out.context_hash, str)
    assert len(out.context_hash) > 0
