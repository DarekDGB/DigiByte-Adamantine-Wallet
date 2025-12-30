from core.runtime.capabilities import issue_runtime_capability


def test_runtime_capability_is_bound_to_scope_hash():
    cap = issue_runtime_capability(scope_hash="scope-A")
    assert cap.scope_hash == "scope-A"
    assert isinstance(cap.token, str)
    assert len(cap.token) > 10
