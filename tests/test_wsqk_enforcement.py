import pytest

from core.eqc.engine import EQCEngine
from core.eqc.context import (
    EQCContext,
    ActionContext,
    DeviceContext,
    NetworkContext,
    UserContext,
)
from core.wsqk.context_bind import bind_scope_from_eqc
from core.wsqk.executor import execute_with_scope, WSQKExecutionError


def _ctx(
    device_type: str = "mobile",
    trusted: bool = True,
    action: str = "send",
    asset: str = "DGB",
    amount: int = 1000,
    recipient: str = "DGB1-test",
) -> EQCContext:
    return EQCContext(
        action=ActionContext(action=action, asset=asset, amount=amount, recipient=recipient),
        device=DeviceContext(
            device_type=device_type,
            trusted=trusted,
            os="ios",
            app_version="0.1.0",
        ),
        network=NetworkContext(
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


def test_wsqk_blocks_when_wallet_id_mismatch():
    engine = EQCEngine()
    ctx = _ctx(device_type="mobile", trusted=True)

    decision = engine.decide(ctx)
    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id="wallet-1",
        action="send",
        ttl_seconds=60,
    )

    def executor(_context: EQCContext):
        return {"ok": True}

    with pytest.raises(WSQKExecutionError):
        execute_with_scope(
            scope=bound.scope,
            context=ctx,
            wallet_id="wallet-2",  # mismatch
            action="send",
            executor=executor,
        )


def test_wsqk_blocks_when_context_hash_mismatch():
    engine = EQCEngine()
    ctx1 = _ctx(device_type="mobile", trusted=True, recipient="DGB1-A")
    ctx2 = _ctx(device_type="mobile", trusted=True, recipient="DGB1-B")  # different -> different context_hash

    decision = engine.decide(ctx1)
    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id="wallet-1",
        action="send",
        ttl_seconds=60,
    )

    def executor(_context: EQCContext):
        return {"ok": True}

    with pytest.raises(WSQKExecutionError):
        execute_with_scope(
            scope=bound.scope,
            context=ctx2,  # mismatch
            wallet_id="wallet-1",
            action="send",
            executor=executor,
        )


def test_wsqk_blocks_when_scope_expired_ttl():
    engine = EQCEngine()
    ctx = _ctx(device_type="mobile", trusted=True)

    decision = engine.decide(ctx)
    # ttl_seconds=-1 ensures "already expired" without needing sleep/time mocking
    bound = bind_scope_from_eqc(
        decision=decision,
        wallet_id="wallet-1",
        action="send",
        ttl_seconds=-1,
    )

    def executor(_context: EQCContext):
        return {"ok": True}

    with pytest.raises(WSQKExecutionError):
        execute_with_scope(
            scope=bound.scope,
            context=ctx,
            wallet_id="wallet-1",
            action="send",
            executor=executor,
        )
