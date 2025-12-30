from core.eqc.engine import EQCEngine
from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.wsqk.context_bind import bind_scope_from_eqc
from core.wsqk.session import WSQKSession
from core.wsqk.guard import execute_guarded


def _ctx() -> EQCContext:
    return EQCContext(
        action=ActionContext(action="send", asset="DGB", amount=1, recipient="DGB1-test"),
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


def test_guard_executes_with_scope_bound_capability():
    engine = EQCEngine()
    decision = engine.decide(_ctx())
    bound = bind_scope_from_eqc(decision=decision, wallet_id="wallet-1", action="send", ttl_seconds=60)

    session = WSQKSession(ttl_seconds=60)
    nonce = session.issue_nonce(scope_hash=bound.scope.scope_hash())

    out = execute_guarded(
        scope=bound.scope,
        session=session,
        nonce=nonce,
        context=_ctx(),
        wallet_id="wallet-1",
        action="send",
        executor=lambda _c: {"ok": True},
    )

    assert out.result == {"ok": True}
