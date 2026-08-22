from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

MAX_CANONICAL_RECEIPT_BYTES = 131_072
MAX_SNAPSHOT_SCALAR_BYTES = 131_072
MAX_TEXT_FIELD_BYTES = 8_192
MAX_SIGNATURE_BUNDLE_BYTES = 32_768
MAX_CONTAINER_DEPTH = 16
MAX_CONTAINER_NODES = 4_096
MAX_SIGNED_INTEGER_BITS = 64
EXPECTED_COMPONENT_BUNDLE_COUNT = 5
EXPECTED_RECEIPT_BUNDLE_COUNT = 1
MIN_SIGNATURES_PER_BUNDLE = 2
MAX_SIGNATURES_PER_BUNDLE = 3
MAX_SIGNATURE_BUNDLES = 6
MAX_VERIFICATION_CALLS = 18
MAX_PQC_VERIFICATION_CALLS = 12
MAX_TRUSTED_REGISTRY_ENTRIES = 64
MAX_REPLAY_IDENTIFIERS = 4_096
MAX_DENYLIST_ENTRIES = 4_096


class ShieldV4WorkBudgetError(ValueError):
    """Untrusted verification input exceeded the frozen Shield v4 work budget."""


def require_bounded_text(value: Any, *, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ShieldV4WorkBudgetError(f"{field_name} must be exact non-empty string")
    if len(value) > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4WorkBudgetError(f"{field_name} exceeds text byte budget")
    try:
        encoded_length = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise ShieldV4WorkBudgetError(f"{field_name} must be valid UTF-8 text") from exc
    if encoded_length > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4WorkBudgetError(f"{field_name} exceeds text byte budget")
    return value


def require_signed_integer(value: Any, *, field_name: str) -> int:
    if type(value) is not int:
        raise ShieldV4WorkBudgetError(f"{field_name} must be exact integer")
    lower_bound = -(1 << (MAX_SIGNED_INTEGER_BITS - 1))
    upper_bound = (1 << (MAX_SIGNED_INTEGER_BITS - 1)) - 1
    if not lower_bound <= value <= upper_bound:
        raise ShieldV4WorkBudgetError(f"{field_name} exceeds signed integer budget")
    return value


def require_byte_budget(
    payload: bytes,
    *,
    maximum: int,
    field_name: str,
) -> bytes:
    if type(payload) is not bytes:
        raise ShieldV4WorkBudgetError(f"{field_name} must be exact bytes")
    if len(payload) > maximum:
        raise ShieldV4WorkBudgetError(f"{field_name} exceeds byte budget")
    return payload


@dataclass
class _SnapshotBudget:
    nodes: int = 0
    scalar_bytes: int = 0
    active_container_ids: set[int] = field(default_factory=set)

    def _consume_node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_CONTAINER_NODES:
            raise ShieldV4WorkBudgetError("JSON node budget exceeded")

    def _consume_scalar_bytes(self, size: int) -> None:
        self.scalar_bytes += size
        if self.scalar_bytes > MAX_SNAPSHOT_SCALAR_BYTES:
            raise ShieldV4WorkBudgetError("JSON scalar byte budget exceeded")

    def _text_size(self, value: str) -> int:
        if len(value) > MAX_TEXT_FIELD_BYTES:
            raise ShieldV4WorkBudgetError("JSON text field exceeds byte budget")
        try:
            size = len(value.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise ShieldV4WorkBudgetError("JSON text must be valid UTF-8") from exc
        if size > MAX_TEXT_FIELD_BYTES:
            raise ShieldV4WorkBudgetError("JSON text field exceeds byte budget")
        return size

    def snapshot(self, value: Any, *, depth: int) -> Any:
        if depth > MAX_CONTAINER_DEPTH:
            raise ShieldV4WorkBudgetError("JSON depth budget exceeded")
        self._consume_node()

        if type(value) is str:
            self._consume_scalar_bytes(self._text_size(value))
            return value
        if type(value) is bool:
            self._consume_scalar_bytes(4 if value else 5)
            return value
        if type(value) is int:
            require_signed_integer(value, field_name="JSON integer")
            self._consume_scalar_bytes(len(str(value).encode("ascii")))
            return value
        if value is None:
            self._consume_scalar_bytes(4)
            return None

        if type(value) is dict:
            return self._snapshot_dict(value, depth=depth)
        if type(value) is list:
            return self._snapshot_list(value, depth=depth)
        raise ShieldV4WorkBudgetError("JSON value uses unsupported type")

    def _enter_container(self, value: Any) -> int:
        identity = id(value)
        if identity in self.active_container_ids:
            raise ShieldV4WorkBudgetError("JSON container cycle rejected")
        self.active_container_ids.add(identity)
        return identity

    def _snapshot_dict(self, value: dict[Any, Any], *, depth: int) -> dict[str, Any]:
        identity = self._enter_container(value)
        try:
            declared_length = len(value)
            if declared_length > MAX_CONTAINER_NODES:
                raise ShieldV4WorkBudgetError("JSON mapping exceeds node budget")
            output: dict[str, Any] = {}
            item_count = 0
            for key, item in value.items():
                item_count += 1
                if item_count > MAX_CONTAINER_NODES:  # pragma: no cover - exact built-in length guards this.
                    raise ShieldV4WorkBudgetError("JSON mapping exceeds node budget")
                if type(key) is not str:
                    raise ShieldV4WorkBudgetError("JSON mapping key must be exact string")
                self._consume_scalar_bytes(self._text_size(key))
                if key in output:  # pragma: no cover - built-in dictionaries cannot yield duplicate keys.
                    raise ShieldV4WorkBudgetError("JSON mapping yielded duplicate key")
                output[key] = self.snapshot(item, depth=depth + 1)
            if item_count != declared_length or len(value) != declared_length:  # pragma: no cover - concurrent mutation guard.
                raise ShieldV4WorkBudgetError("JSON mapping changed during snapshot")
            return output
        finally:
            self.active_container_ids.discard(identity)

    def _snapshot_list(self, value: list[Any], *, depth: int) -> list[Any]:
        identity = self._enter_container(value)
        try:
            declared_length = len(value)
            if declared_length > MAX_CONTAINER_NODES:
                raise ShieldV4WorkBudgetError("JSON list exceeds node budget")
            output: list[Any] = []
            for item in value:
                if len(output) >= MAX_CONTAINER_NODES:  # pragma: no cover - node budget rejects first.
                    raise ShieldV4WorkBudgetError("JSON list exceeds node budget")
                output.append(self.snapshot(item, depth=depth + 1))
            if len(output) != declared_length or len(value) != declared_length:  # pragma: no cover - concurrent mutation guard.
                raise ShieldV4WorkBudgetError("JSON list changed during snapshot")
            return output
        finally:
            self.active_container_ids.discard(identity)


def bounded_json_snapshot(value: Any, *, field_name: str) -> Any:
    """Copy bounded JSON one scalar at a time before canonicalization or callbacks."""

    budget = _SnapshotBudget()
    try:
        return budget.snapshot(value, depth=1)
    except ShieldV4WorkBudgetError:
        raise
    except Exception:
        raise ShieldV4WorkBudgetError(f"{field_name} snapshot failed") from None


def bounded_identifier_set(
    values: Iterable[str],
    *,
    maximum: int,
    field_name: str,
) -> frozenset[str]:
    """Consume no more than ``maximum + 1`` untrusted iterable entries."""

    if isinstance(values, (str, bytes, bytearray, dict)):
        raise ShieldV4WorkBudgetError(f"{field_name} must be an identifier iterable")
    try:
        iterator = iter(values)
    except Exception:
        raise ShieldV4WorkBudgetError(f"{field_name} iterable failed") from None
    output: set[str] = set()
    try:
        for index in range(maximum + 1):
            try:
                value = next(iterator)
            except StopIteration:
                return frozenset(output)
            if index == maximum:
                raise ShieldV4WorkBudgetError(f"{field_name} entry budget exceeded")
            output.add(require_bounded_text(value, field_name=f"{field_name} entry"))
    except ShieldV4WorkBudgetError:
        raise
    except Exception:
        raise ShieldV4WorkBudgetError(f"{field_name} iteration failed") from None
    raise AssertionError("bounded identifier loop must return or reject")  # pragma: no cover
