import pytest

from core.eqc.engine import EQCEngine
from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.eqc.verdicts import VerdictType
from core.wsqk.context_bind import bind_scope_from_eqc
from core.wsqk.session import WSQKSession
from core.wsqk.guard import execute_guarded, WSQKGuardError


def _ctx() -> EQCContext:
    return EQCContext(
        action=ActionContext(action="send", asset="DGB", amount=1_000, recipient="DGB1-test"),
        device=DeviceContext(
            device_type="mobile",
            trusted=True,
            os="ios",
            app_version="0.1.0",
        ),
        network=NetworkContext(
            network="mainnet",
            node_type="local",
            node_trusted=True,
            entropy_score=0.9,
            peer_count=8,
        ),
        user=UserContext(
            user_id="user-1",
            biometric_available=True,
            pin_set=True,
        ),
        timestamp=1766877694,
        extra={},
    )


def test_complete_eqc_wsqk_path_replay_is_blocked():
    engine = EQCEngine()
    ctx = _ctx()

    # 1) EQC decides
    decision = engine.decide(ctx)
    assert decision.verdict.type == VerdictType.ALLOW

    # 2) Bind scope from decision
    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id="wallet-1",
        action="send",
        ttl_seconds=60,
    )

    # 3) Create WSQK session + issue nonce (single-use)
    session = WSQKSession(wallet_id="wallet-1")
    nonce = session.issue_nonce(scope_hash=bound.scope.scope_hash())

    # 4) Execute under guard (first call succeeds)
    def executor(_context: EQCContext):
        return {"ok": True}

    out = execute_guarded(
        scope=bound.scope,
        session=session,
        nonce=nonce,
        context=ctx,
        wallet_id="wallet-1",
        action="send",
        executor=executor,
    )
    assert out.result == {"ok": True}

    # 5) Replay attempt (same nonce) must fail
    with pytest.raises(WSQKGuardError):
        execute_guarded(
            scope=bound.scope,
            session=session,
            nonce=nonce,  # replay the same nonce
            context=ctx,
            wallet_id="wallet-1",
            action="send",
            executor=executor,
        )
