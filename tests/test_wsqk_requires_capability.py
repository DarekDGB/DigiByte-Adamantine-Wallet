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


def test_wsqk_execution_fails_without_runtime_capability():
    with pytest.raises(WSQKExecutionError):
        execute_with_scope(
            scope=FakeScope(),
            context=FakeContext(),
            wallet_id="wallet1",
            action="sign",
            executor=lambda ctx: "should_not_run",
            capability=None,
        )


def test_wsqk_execution_succeeds_with_runtime_capability():
    scope = FakeScope()
    cap = issue_runtime_capability(scope_hash=scope.scope_hash())

    out = execute_with_scope(
        scope=scope,
        context=FakeContext(),
        wallet_id="wallet1",
        action="sign",
        executor=lambda ctx: "ok",
        capability=cap,
    )

    assert out.result == "ok"
