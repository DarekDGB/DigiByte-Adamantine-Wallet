from core.wallet.discovery import discover_used_indices


class FakeProvider:
    def __init__(self, used: set[str]) -> None:
        self._used = used

    def is_used(self, address: str) -> bool:
        return address in self._used


def test_discovery_stops_after_gap_limit():
    # Address function: "A0", "A1", ...
    def addr_at(i: int) -> str:
        return f"A{i}"

    # Mark only A0 and A2 as used
    provider = FakeProvider(used={"A0", "A2"})

    res = discover_used_indices(provider, addr_at, gap_limit=3, start_index=0, max_scan=50)

    assert res.used_indices == [0, 2]
    assert res.last_used_index == 2
    # stop after 3 consecutive unused after the last scan window
    assert res.scanned_count >= 3


def test_discovery_with_no_used_addresses():
    def addr_at(i: int) -> str:
        return f"A{i}"

    provider = FakeProvider(used=set())
    res = discover_used_indices(provider, addr_at, gap_limit=5, start_index=0, max_scan=50)

    assert res.used_indices == []
    assert res.last_used_index is None
    assert res.scanned_count == 5
