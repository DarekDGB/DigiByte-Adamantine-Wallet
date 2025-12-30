import pytest

from core.wsqk.executor import execute_with_scope, WSQKExecutionError
from core.runtime.capabilities import issue_runtime_capability


class FakeScope:
    def assert_active(self, now=None):
        return None

    def assert_wallet(self, wallet_id):
        return None

    def assert_action(self, action):
        return None

    def assert_context(self, context_hash):
        return None

    def scope_hash(self):
        return "scope-A"


class FakeContext:
    def context_hash(self):
        return "deadbeef"


def test_wsqk_blocks_expired_capability():
    scope = FakeScope()
    ctx = FakeContext()

    cap = issue_runtime_capability(scope_hash=scope.scope_hash(), ttl_seconds=1, issued_at=1000)

    with pytest.raises(WSQKExecutionError):
        execute_with_scope(
            scope=scope,
            context=ctx,
            wallet_id="wallet1",
            action="sign",
            executor=lambda _c: "nope",
            capability=cap,
            now=1002,
        )
