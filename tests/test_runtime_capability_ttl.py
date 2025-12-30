import pytest

from core.runtime.capabilities import issue_runtime_capability


def test_capability_without_ttl_is_not_expired():
    cap = issue_runtime_capability(scope_hash="scope-A", ttl_seconds=None, issued_at=1000)
    cap.assert_valid(now=999999)
    assert cap.is_expired(now=999999) is False


def test_capability_with_ttl_expires():
    cap = issue_runtime_capability(scope_hash="scope-A", ttl_seconds=1, issued_at=1000)

    # still valid at issued_at and issued_at+1
    cap.assert_valid(now=1000)
    cap.assert_valid(now=1001)

    # expired after ttl window
    assert cap.is_expired(now=1002) is True
    with pytest.raises(ValueError):
        cap.assert_valid(now=1002)
