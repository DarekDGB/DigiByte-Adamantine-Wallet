from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable

import pytest

import adamantine.v1.contracts.shield_orchestrator_receipt_v4 as contract_module
import adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier as verifier_module
import adamantine.v1.integrations.shield_v4_real_crypto_backend as real_backend_module
import adamantine.v1.integrations.shield_v4_verification_audit as audit_module
import adamantine.v1.integrations.shield_v4_work_budget as budget_module
from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    ALLOWED_ALGORITHMS,
    COMPONENT_ROLES,
    MAX_SIGNATURE_BUNDLE_BYTES,
    ShieldV4ReceiptContractError,
    _require_signature_encoding,
    preflight_shield_v4_receipt_contract,
    validate_preflighted_shield_v4_receipt_integrity,
    validate_shield_v4_receipt_contract,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    ORCHESTRATOR_ROLE,
    ShieldV4ReceiptVerificationState,
    _VerificationCallBudget,
    _VerifierRejection,
    _preflight_receipt_bundles,
    _resolve_verification_bundles,
    _verify_shield_v4_orchestrator_receipt,
    _verify_global_algorithm_waves,
    _verify_test_only_signature,
    load_trusted_shield_v4_key_registry,
    verify_shield_v4_orchestrator_receipt,
)
from adamantine.v1.integrations.shield_v4_real_crypto_backend import (
    REAL_SIGNATURE_ENCODING_PREFIX,
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoMaterialError,
    decode_binary_signature_material,
    encode_binary_signature_material,
    reject_test_only_key_material,
)
from adamantine.v1.integrations.shield_v4_verification_audit import (
    AUDIT_ACK_SCHEMA_VERSION,
    V4_VERIFY_OK,
    _TranscriptCapture,
    audit_batch_sha256,
    verify_shield_v4_orchestrator_receipt_with_audit,
)
from adamantine.v1.integrations.shield_v4_work_budget import (
    MAX_CANONICAL_RECEIPT_BYTES,
    MAX_CONTAINER_DEPTH,
    MAX_CONTAINER_NODES,
    MAX_DENYLIST_ENTRIES,
    MAX_PQC_VERIFICATION_CALLS,
    MAX_REPLAY_IDENTIFIERS,
    MAX_SIGNATURES_PER_BUNDLE,
    MAX_SNAPSHOT_SCALAR_BYTES,
    MAX_TEXT_FIELD_BYTES,
    MAX_TRUSTED_REGISTRY_ENTRIES,
    MAX_VERIFICATION_CALLS,
    ShieldV4WorkBudgetError,
    _SnapshotBudget,
    bounded_identifier_set,
    bounded_json_snapshot,
    require_bounded_text,
    require_byte_budget,
    require_signed_integer,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "src" / "adamantine" / "v1" / "fixtures" / "shield_v4"
TRANSPORT_HASH = "b" * 64
CANONICAL_BUNDLE_ORDER = (
    "adn",
    "dqsn",
    "guardian_wallet",
    "qwg",
    "sentinel_ai",
    "shield_orchestrator",
)
CANONICAL_ROLE_ORDER = tuple(
    COMPONENT_ROLES[component_id] for component_id in CANONICAL_BUNDLE_ORDER[:-1]
) + (ORCHESTRATOR_ROLE,)


def _flow(name: str = "full_multi_repo_v4_allow_flow.json") -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class _Sink:
    def __init__(self) -> None:
        self.records: tuple[bytes, ...] = ()

    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        self.records = records
        return {
            "schema_version": AUDIT_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


def _run(
    flow: dict[str, Any],
    *,
    receipt: Any | None = None,
    registry: Any | None = None,
    seen_request_ids: Iterable[str] = (),
    rejected_receipt_hashes: Iterable[str] = (),
    verification_time: str | None = None,
    callback: Callable[[Any, Any], bool] | None = None,
) -> tuple[Any, list[tuple[str, str]]]:
    calls: list[tuple[str, str]] = []

    def recording_callback(entry: Any, key: Any) -> bool:
        calls.append((str(entry["algorithm"]), key.role))
        if callback is not None:
            return callback(entry, key)
        return _verify_test_only_signature(entry, key)

    result = verify_shield_v4_orchestrator_receipt(
        flow["receipt"] if receipt is None else receipt,
        expected_context_hash=flow["expected_context_hash"],
        expected_request_id=flow["expected_request_id"],
        trusted_key_registry=(
            flow["trusted_key_registry"] if registry is None else registry
        ),
        verification_time=(
            flow["verification_time"]
            if verification_time is None
            else verification_time
        ),
        seen_request_ids=seen_request_ids,
        rejected_receipt_hashes=rejected_receipt_hashes,
        signature_verifier=recording_callback,
    )
    return result, calls


@pytest.mark.parametrize(
    ("fixture_name", "expected_calls", "expected_pqc"),
    (
        ("full_multi_repo_v4_allow_flow.json", 12, 6),
        ("full_multi_repo_v4_fn_dsa_allow_flow.json", 18, 12),
    ),
)
def test_v410c_audited_global_algorithm_waves_have_exact_budgets_and_order(
    fixture_name: str,
    expected_calls: int,
    expected_pqc: int,
) -> None:
    flow = _flow(fixture_name)
    sink = _Sink()
    callback_calls: list[tuple[str, str]] = []

    def callback(entry: Any, key: Any) -> bool:
        callback_calls.append((str(entry["algorithm"]), key.role))
        return _verify_test_only_signature(entry, key)

    result = verify_shield_v4_orchestrator_receipt_with_audit(
        flow["receipt"],
        expected_context_hash=flow["expected_context_hash"],
        expected_request_id=flow["expected_request_id"],
        trusted_key_registry=flow["trusted_key_registry"],
        verification_time=flow["verification_time"],
        audit_sink=sink,
        artifact_transport_hash=TRANSPORT_HASH,
        signature_verifier=callback,
    )

    present_algorithms = ALLOWED_ALGORITHMS[: expected_calls // 6]
    expected_order = [
        (algorithm, role)
        for algorithm in present_algorithms
        for role in CANONICAL_ROLE_ORDER
    ]
    assert result.accepted_as_evidence is True
    assert result.final_approval is False
    assert callback_calls == expected_order
    assert len(callback_calls) == expected_calls
    assert sum(algorithm != "classical-ed25519" for algorithm, _ in callback_calls) == expected_pqc

    events = [json.loads(record.decode("utf-8")) for record in sink.records]
    signature_events = [
        event for event in events if event["event_type"] == "signature_verification"
    ]
    assert len(events) == expected_calls + 2
    assert [event["artifact_id"] for event in signature_events] == [
        bundle_id
        for _algorithm in present_algorithms
        for bundle_id in CANONICAL_BUNDLE_ORDER
    ]
    assert [event["algorithm"] for event in signature_events] == [
        algorithm
        for algorithm in present_algorithms
        for _bundle_id in CANONICAL_BUNDLE_ORDER
    ]
    assert all(event["reason_id"] == V4_VERIFY_OK for event in signature_events)


def _install_forbidden_integrity(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}

    def forbidden_canonical(_payload: Any) -> str:
        calls["canonical"] += 1
        raise AssertionError("canonicalization must not run during cheap preflight")

    def forbidden_receipt_hash(_payload: Any) -> str:
        calls["receipt_hash"] += 1
        raise AssertionError("receipt hash must not run during cheap preflight")

    def forbidden_signed_hash(*, domain_tag: str, payload: Any) -> str:
        del domain_tag, payload
        calls["signed_hash"] += 1
        raise AssertionError("signed hash must not run during cheap preflight")

    monkeypatch.setattr(contract_module, "to_canonical_json", forbidden_canonical)
    monkeypatch.setattr(contract_module, "receipt_hash", forbidden_receipt_hash)
    monkeypatch.setattr(contract_module, "signed_payload_hash", forbidden_signed_hash)
    return calls


@pytest.mark.parametrize(
    "failure",
    ("missing", "revoked", "expired", "replay", "denylist", "freshness"),
)
def test_v410c_all_cheap_gates_finish_before_any_canonical_or_hash_work(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    registry = copy.deepcopy(flow["trusted_key_registry"])
    seen: Iterable[str] = ()
    denylist: Iterable[str] = ()
    verification_time = flow["verification_time"]
    target = next(
        entry
        for entry in registry["entries"]
        if entry["role"] == ORCHESTRATOR_ROLE and entry["algorithm"] == "ml-dsa"
    )
    if failure == "missing":
        registry["entries"].remove(target)
    elif failure == "revoked":
        target["status"] = "revoked"
    elif failure == "expired":
        target["not_after"] = "2026-06-20T23:59:59Z"
    elif failure == "replay":
        seen = (flow["expected_request_id"],)
    elif failure == "denylist":
        denylist = (flow["receipt"]["receipt_hash"],)
    else:
        verification_time = "2026-06-22T00:02:00Z"

    integrity_calls = _install_forbidden_integrity(monkeypatch)
    key_lookups = 0
    original_find_key = verifier_module._find_key

    def recording_find_key(*args: Any, **kwargs: Any) -> Any:
        nonlocal key_lookups
        key_lookups += 1
        return original_find_key(*args, **kwargs)

    monkeypatch.setattr(verifier_module, "_find_key", recording_find_key)
    result, callback_calls = _run(
        flow,
        registry=registry,
        seen_request_ids=seen,
        rejected_receipt_hashes=denylist,
        verification_time=verification_time,
    )

    assert result.accepted_as_evidence is False
    assert callback_calls == []
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}
    if failure == "missing":
        assert key_lookups == 12


def test_v410c_late_bundle_profile_failure_precedes_trust_hash_and_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    receipt["signature_bundle"]["signatures"][-1]["standard_profile"] = "wrong"
    integrity_calls = _install_forbidden_integrity(monkeypatch)
    key_lookups = 0

    def forbidden_find_key(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal key_lookups
        key_lookups += 1
        raise AssertionError("key lookup must not run")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_find_key)
    result, callback_calls = _run(flow, receipt=receipt)

    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert callback_calls == []
    assert key_lookups == 0
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}


def test_v410c_public_duplicate_optional_algorithm_cannot_multiply_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    signatures = receipt["signature_bundle"]["signatures"]
    signatures[1] = copy.deepcopy(signatures[2])
    integrity_calls = _install_forbidden_integrity(monkeypatch)
    key_lookups = 0

    def forbidden_find_key(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal key_lookups
        key_lookups += 1
        raise AssertionError("key lookup must not run")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_find_key)
    result, callback_calls = _run(flow, receipt=receipt)

    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert callback_calls == []
    assert key_lookups == 0
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}


class _CountingIdentifiers:
    def __init__(self, count: int) -> None:
        self.count = count
        self.consumed = 0

    def __iter__(self):
        for index in range(self.count):
            self.consumed += 1
            yield f"identifier-{index}"


class _RaisingIdentifiers:
    def __iter__(self):
        yield "one"
        raise RuntimeError("untrusted iterator detail")


def test_v410c_replay_and_denylist_iterables_are_bounded_and_sanitized() -> None:
    flow = _flow()
    over_replay = _CountingIdentifiers(MAX_REPLAY_IDENTIFIERS + 1)
    result, calls = _run(flow, seen_request_ids=over_replay)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id is ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert calls == []
    assert over_replay.consumed == MAX_REPLAY_IDENTIFIERS + 1

    over_denylist = _CountingIdentifiers(MAX_DENYLIST_ENTRIES + 1)
    result, calls = _run(flow, rejected_receipt_hashes=over_denylist)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert calls == []
    assert over_denylist.consumed == MAX_DENYLIST_ENTRIES + 1

    for values, argument in (
        (_RaisingIdentifiers(), "seen_request_ids"),
        (123, "rejected_receipt_hashes"),
    ):
        kwargs = {argument: values}
        result, calls = _run(flow, **kwargs)
        assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
        assert calls == []


def test_v410c_registry_exact_limit_and_overcount_are_fail_closed() -> None:
    flow = _flow()
    registry = copy.deepcopy(flow["trusted_key_registry"])
    template = copy.deepcopy(registry["entries"][0])
    while len(registry["entries"]) < MAX_TRUSTED_REGISTRY_ENTRIES:
        extra = copy.deepcopy(template)
        extra["key_id"] = f"unused-limit-key-{len(registry['entries'])}"
        extra["key_version"] = len(registry["entries"]) + 100
        registry["entries"].append(extra)
    result, calls = _run(flow, registry=registry)
    assert result.accepted_as_evidence is True
    assert len(calls) == 12

    registry["entries"].append(copy.deepcopy(template))
    result, calls = _run(flow, registry=registry)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert calls == []


def test_v410c_empty_signature_public_key_and_hostile_registry_reject_cheaply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    integrity_calls = _install_forbidden_integrity(monkeypatch)

    receipt = copy.deepcopy(flow["receipt"])
    receipt["signature_bundle"]["signatures"][-1]["signature"] = ""
    result, calls = _run(flow, receipt=receipt)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert calls == []

    registry = copy.deepcopy(flow["trusted_key_registry"])
    registry["entries"][-1]["public_key"] = ""
    result, calls = _run(flow, registry=registry)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert calls == []

    class HostileRegistry(dict):
        def items(self):
            raise AssertionError("registry subclass operation must not run")

    result, calls = _run(
        flow,
        registry=HostileRegistry(copy.deepcopy(flow["trusted_key_registry"])),
    )
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert calls == []
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}


def _invalid_receipt_shapes(flow: dict[str, Any]) -> tuple[Any, ...]:
    oversized_value = copy.deepcopy(flow["receipt"])
    oversized_value["component_verdicts"][0]["metadata"]["large"] = "x" * (
        MAX_TEXT_FIELD_BYTES + 1
    )

    oversized_key = copy.deepcopy(flow["receipt"])
    oversized_key["component_verdicts"][0]["metadata"][
        "k" * (MAX_TEXT_FIELD_BYTES + 1)
    ] = ""

    scalar_overcount = copy.deepcopy(flow["receipt"])
    scalar_overcount["component_verdicts"][0]["metadata"] = {
        f"chunk-{index}": "x" * 8_000 for index in range(17)
    }

    too_deep = copy.deepcopy(flow["receipt"])
    nested: dict[str, Any] = {}
    too_deep["component_verdicts"][0]["metadata"] = nested
    for _ in range(MAX_CONTAINER_DEPTH + 1):
        child: dict[str, Any] = {}
        nested["child"] = child
        nested = child

    cyclic = copy.deepcopy(flow["receipt"])
    cyclic_metadata: dict[str, Any] = {}
    cyclic_metadata["cycle"] = cyclic_metadata
    cyclic["component_verdicts"][0]["metadata"] = cyclic_metadata

    too_many_nodes = copy.deepcopy(flow["receipt"])
    too_many_nodes["component_verdicts"][0]["metadata"]["nodes"] = [
        None
    ] * MAX_CONTAINER_NODES

    large_integer = copy.deepcopy(flow["receipt"])
    large_integer["key_registry_version"] = 1 << 63

    class HostileDict(dict):
        def items(self):
            raise AssertionError("dict subclass operation must not run")

    hostile = HostileDict(copy.deepcopy(flow["receipt"]))
    return (
        oversized_value,
        oversized_key,
        scalar_overcount,
        too_deep,
        cyclic,
        too_many_nodes,
        large_integer,
        hostile,
    )


def test_v410c_structural_limits_reject_before_materialization_or_callbacks() -> None:
    flow = _flow()
    for receipt in _invalid_receipt_shapes(flow):
        result, calls = _run(flow, receipt=receipt)
        assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
        assert result.reason_id is ReasonId.EQC_INVALID_SHIELD_BUNDLE
        assert calls == []


def test_v410c_exact_canonical_receipt_and_bundle_limits_reject_with_zero_callbacks() -> None:
    flow = _flow()
    receipt = copy.deepcopy(flow["receipt"])
    receipt["component_verdicts"][0]["metadata"] = {
        f"escaped-{index}": "\x01" * 7_000 for index in range(14)
    }
    snapshot = bounded_json_snapshot(receipt, field_name="receipt")
    assert len(contract_module.to_canonical_json(snapshot).encode()) > MAX_CANONICAL_RECEIPT_BYTES
    result, calls = _run(flow, receipt=receipt)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert calls == []

    receipt = copy.deepcopy(flow["receipt"])
    registry = copy.deepcopy(flow["trusted_key_registry"])
    signatures = receipt["signature_bundle"]["signatures"]
    for index, entry in enumerate(signatures):
        old_key_id = entry["key_id"]
        new_key_id = chr(ord("a") + index) * 8_000
        entry["key_id"] = new_key_id
        entry["signature"] = REAL_SIGNATURE_ENCODING_PREFIX + "A" * 8_187
        registry_entry = next(
            item
            for item in registry["entries"]
            if item["role"] == ORCHESTRATOR_ROLE
            and item["algorithm"] == entry["algorithm"]
            and item["key_id"] == old_key_id
        )
        registry_entry["key_id"] = new_key_id
    assert (
        len(contract_module.to_canonical_json(receipt["signature_bundle"]).encode())
        > MAX_SIGNATURE_BUNDLE_BYTES
    )
    result, calls = _run(flow, receipt=receipt, registry=registry)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert calls == []


def test_v410c_callback_budget_counts_exceptions_and_pqc_immediately() -> None:
    total_budget = _VerificationCallBudget()
    for _ in range(MAX_VERIFICATION_CALLS):
        total_budget.before_callback("classical-ed25519")
    with pytest.raises(_VerifierRejection, match="work budget"):
        total_budget.before_callback("classical-ed25519")
    assert total_budget.total_calls == MAX_VERIFICATION_CALLS + 1

    pqc_budget = _VerificationCallBudget()
    for _ in range(MAX_PQC_VERIFICATION_CALLS):
        pqc_budget.before_callback("ml-dsa")
    with pytest.raises(_VerifierRejection, match="work budget"):
        pqc_budget.before_callback("fn-dsa")
    assert pqc_budget.pqc_calls == MAX_PQC_VERIFICATION_CALLS + 1

    flow = _flow()
    callback_calls = 0

    def raising_callback(_entry: Any, _key: Any) -> bool:
        nonlocal callback_calls
        callback_calls += 1
        if callback_calls == 7:
            raise RuntimeError("backend detail")
        return True

    result, calls = _run(flow, callback=raising_callback)
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.dominant_reason_ids == ("signature verifier failed closed",)
    assert callback_calls == 7
    assert len(calls) == 7


def test_v410c_internal_count_guards_cover_impossible_dataclass_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    prepared = _preflight_receipt_bundles(flow["receipt"])
    registry = load_trusted_shield_v4_key_registry(flow["trusted_key_registry"])
    kwargs = {"registry": registry, "verification_time": flow["verification_time"]}

    with pytest.raises(_VerifierRejection, match="bundle count"):
        _resolve_verification_bundles(
            replace(prepared, components=prepared.components[:-1]),
            **kwargs,
        )
    duplicate_component = replace(
        prepared.components[-1],
        component_id=prepared.components[0].component_id,
    )
    with pytest.raises(_VerifierRejection, match="component bundle set"):
        _resolve_verification_bundles(
            replace(
                prepared,
                components=prepared.components[:-1] + (duplicate_component,),
            ),
            **kwargs,
        )
    monkeypatch.setattr(verifier_module, "MAX_SIGNATURE_BUNDLES", 7)
    with pytest.raises(_VerifierRejection, match="bundle count"):
        _resolve_verification_bundles(prepared, **kwargs)
    monkeypatch.setattr(verifier_module, "MAX_SIGNATURE_BUNDLES", 6)
    oversized_bundle = replace(
        prepared.components[0].bundle,
        entries=prepared.components[0].bundle.entries * 10,
    )
    with pytest.raises(_VerifierRejection, match="work budget"):
        _resolve_verification_bundles(
            replace(
                prepared,
                components=(
                    replace(prepared.components[0], bundle=oversized_bundle),
                    *prepared.components[1:],
                ),
            ),
            **kwargs,
        )

    resolved = _resolve_verification_bundles(prepared, **kwargs)
    duplicated = replace(
        resolved[0],
        resolved_entries=(resolved[0].resolved_entries[0],) * 2
        + resolved[0].resolved_entries[1:],
    )
    with pytest.raises(_VerifierRejection, match="duplicate signature algorithm"):
        _verify_global_algorithm_waves(
            (duplicated, *resolved[1:]),
            signature_verifier=_verify_test_only_signature,
            transcript_observer=None,
        )


def test_v410c_work_budget_helpers_lock_exact_json_and_iterable_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert bounded_json_snapshot(
        {"": "", "true": True, "false": False, "integer": -1, "null": None},
        field_name="sample",
    ) == {"": "", "true": True, "false": False, "integer": -1, "null": None}
    assert require_bounded_text("x", field_name="text") == "x"
    assert require_signed_integer(-(1 << 63), field_name="integer") == -(1 << 63)
    assert require_signed_integer((1 << 63) - 1, field_name="integer") == (1 << 63) - 1
    assert require_byte_budget(b"x", maximum=1, field_name="bytes") == b"x"
    assert bounded_identifier_set(("a", "a", "b"), maximum=3, field_name="ids") == frozenset({"a", "b"})

    for value in ("", 1):
        with pytest.raises(ShieldV4WorkBudgetError):
            require_bounded_text(value, field_name="text")
    with pytest.raises(ShieldV4WorkBudgetError, match="valid UTF-8"):
        require_bounded_text("\ud800", field_name="text")
    with pytest.raises(ShieldV4WorkBudgetError, match="text byte"):
        require_bounded_text("x" * (MAX_TEXT_FIELD_BYTES + 1), field_name="text")
    with pytest.raises(ShieldV4WorkBudgetError, match="text byte"):
        require_bounded_text(
            "Ã©" * ((MAX_TEXT_FIELD_BYTES // 2) + 1),
            field_name="text",
        )
    huge_ascii = "x" * 4_000_000
    with pytest.raises(ShieldV4WorkBudgetError, match="text byte"):
        require_bounded_text(huge_ascii, field_name="text")
    with pytest.raises(ShieldV4WorkBudgetError, match="text field"):
        bounded_json_snapshot({"huge": huge_ascii}, field_name="sample")
    bounded_text_source = inspect.getsource(require_bounded_text)
    snapshot_text_source = inspect.getsource(_SnapshotBudget._text_size)
    assert bounded_text_source.index("len(value) >") < bounded_text_source.index("value.encode")
    assert snapshot_text_source.index("len(value) >") < snapshot_text_source.index("value.encode")
    for value in (True, 1 << 63, -(1 << 63) - 1):
        with pytest.raises(ShieldV4WorkBudgetError):
            require_signed_integer(value, field_name="integer")
    with pytest.raises(ShieldV4WorkBudgetError, match="exact bytes"):
        require_byte_budget(bytearray(b"x"), maximum=1, field_name="bytes")  # type: ignore[arg-type]
    with pytest.raises(ShieldV4WorkBudgetError, match="byte budget"):
        require_byte_budget(b"xx", maximum=1, field_name="bytes")

    cycle: list[Any] = []
    cycle.append(cycle)
    for value, message in (
        (("tuple",), "unsupported type"),
        ({1: "bad"}, "key must be exact string"),
        ({"bad": "\ud800"}, "valid UTF-8"),
        ({"\ud800": "bad"}, "valid UTF-8"),
        ({"too-long": "x" * (MAX_TEXT_FIELD_BYTES + 1)}, "text field"),
        ({"multibyte": "Ã©" * ((MAX_TEXT_FIELD_BYTES // 2) + 1)}, "text field"),
        (cycle, "cycle"),
        ([None] * (MAX_CONTAINER_NODES + 1), "list exceeds"),
        ({str(index): None for index in range(MAX_CONTAINER_NODES + 1)}, "mapping exceeds"),
        ([None] * MAX_CONTAINER_NODES, "node budget"),
    ):
        with pytest.raises(ShieldV4WorkBudgetError, match=message):
            bounded_json_snapshot(value, field_name="sample")

    nested: Any = "leaf"
    for _ in range(MAX_CONTAINER_DEPTH):
        nested = [nested]
    with pytest.raises(ShieldV4WorkBudgetError, match="depth"):
        bounded_json_snapshot(nested, field_name="sample")
    with pytest.raises(ShieldV4WorkBudgetError, match="scalar byte"):
        bounded_json_snapshot(
            ["x" * 8_000 for _ in range(MAX_SNAPSHOT_SCALAR_BYTES // 8_000 + 1)],
            field_name="sample",
        )

    class DictSubclass(dict):
        pass

    class ListSubclass(list):
        pass

    for value in (DictSubclass(), ListSubclass(), object()):
        with pytest.raises(ShieldV4WorkBudgetError, match="unsupported type"):
            bounded_json_snapshot(value, field_name="sample")

    monkeypatch.setattr(
        _SnapshotBudget,
        "snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("detail")),
    )
    with pytest.raises(ShieldV4WorkBudgetError, match="snapshot failed"):
        bounded_json_snapshot({}, field_name="sample")

    class BadIter:
        def __iter__(self):
            raise RuntimeError("detail")

    for values, message in (
        ("abc", "identifier iterable"),
        (BadIter(), "iterable failed"),
        (_RaisingIdentifiers(), "iteration failed"),
        (("",), "non-empty"),
        (("x", "y"), "entry budget"),
    ):
        maximum = 1 if message == "entry budget" else 3
        with pytest.raises(ShieldV4WorkBudgetError, match=message):
            bounded_identifier_set(values, maximum=maximum, field_name="ids")


def test_v410c_contract_and_real_backend_explicit_encoding_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact_signature = REAL_SIGNATURE_ENCODING_PREFIX + "A" * (
        MAX_TEXT_FIELD_BYTES - len(REAL_SIGNATURE_ENCODING_PREFIX)
    )
    assert len(exact_signature.encode()) == MAX_TEXT_FIELD_BYTES
    assert _require_signature_encoding(exact_signature) == exact_signature
    assert require_bounded_text(
        "x" * MAX_TEXT_FIELD_BYTES,
        field_name="text",
    ) == "x" * MAX_TEXT_FIELD_BYTES
    with pytest.raises(ShieldV4ReceiptContractError, match="encoding budget"):
        _require_signature_encoding("A" * (MAX_TEXT_FIELD_BYTES + 1))
    with pytest.raises(ShieldV4ReceiptContractError, match="standard_profile"):
        contract_module._require_supported_standard_profile(
            algorithm="unknown",
            standard_profile="profile",
        )

    maximum_raw_bytes = (
        (MAX_TEXT_FIELD_BYTES - len(REAL_SIGNATURE_ENCODING_PREFIX)) * 3
    ) // 4
    encoder_calls = 0
    original_encoder = real_backend_module.base64.urlsafe_b64encode

    def forbidden_encoder(_raw: bytes) -> bytes:
        nonlocal encoder_calls
        encoder_calls += 1
        raise AssertionError("base64 encoder must not run")

    monkeypatch.setattr(real_backend_module.base64, "urlsafe_b64encode", forbidden_encoder)
    with pytest.raises(ShieldV4RealCryptoBackendError, match="encoding byte budget"):
        encode_binary_signature_material(b"x" * (maximum_raw_bytes + 1))
    assert encoder_calls == 0
    monkeypatch.setattr(
        real_backend_module.base64,
        "urlsafe_b64encode",
        original_encoder,
    )

    with pytest.raises(ShieldV4RealCryptoBackendError, match="encoding byte budget"):
        decode_binary_signature_material("b64u:" + "A" * MAX_TEXT_FIELD_BYTES)

    key = verifier_module.TrustedShieldV4Key(
        role=ORCHESTRATOR_ROLE,
        key_id="k" * (MAX_TEXT_FIELD_BYTES + 1),
        key_version=1,
        algorithm="ml-dsa",
        not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z",
        status="active",
        public_key="real-public-key",
    )
    with pytest.raises(ShieldV4RealCryptoMaterialError, match="text byte budget"):
        reject_test_only_key_material(key)

    monkeypatch.setattr(
        real_backend_module,
        "require_bounded_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ShieldV4WorkBudgetError("forced"),
        ),
    )
    with pytest.raises(ShieldV4RealCryptoBackendError, match="encoding byte budget"):
        real_backend_module.encode_binary_signature_material(b"x")


def test_v410c_registry_public_key_bound_is_explicit_after_shared_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = copy.deepcopy(_flow()["trusted_key_registry"])
    registry["entries"][0]["public_key"] = "k" * MAX_TEXT_FIELD_BYTES
    loaded = load_trusted_shield_v4_key_registry(registry)
    assert loaded.entries[0].public_key == "k" * MAX_TEXT_FIELD_BYTES

    registry["entries"][0]["public_key"] = "k" * (MAX_TEXT_FIELD_BYTES + 1)
    monkeypatch.setattr(
        verifier_module,
        "bounded_json_snapshot",
        lambda value, *, field_name: value,
    )
    with pytest.raises(_VerifierRejection, match="public key exceeds"):
        load_trusted_shield_v4_key_registry(registry)


def test_v410c_public_verifier_ast_signature_is_unchanged() -> None:
    assert str(inspect.signature(verify_shield_v4_orchestrator_receipt)) == (
        "(receipt: 'Any', *, expected_context_hash: 'str', expected_request_id: 'str', "
        "trusted_key_registry: 'Mapping[str, Any]', verification_time: 'str', "
        "seen_request_ids: 'Iterable[str]' = (), rejected_receipt_hashes: "
        "'Iterable[str]' = (), minimum_key_registry_version: 'int' = 1, "
        "signature_verifier: 'SignatureVerifier | None' = None) -> "
        "'ShieldV4ReceiptVerificationResult'"
    )


def test_v410c_deferred_integrity_helpers_cover_exact_byte_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    checked = preflight_shield_v4_receipt_contract(
        flow["receipt"],
        expected_context_hash=flow["expected_context_hash"],
    )
    monkeypatch.setattr(contract_module, "MAX_CANONICAL_RECEIPT_BYTES", 1)
    with pytest.raises(ShieldV4ReceiptContractError, match="canonical byte budget"):
        validate_preflighted_shield_v4_receipt_integrity(checked)
    with pytest.raises(ShieldV4ReceiptContractError, match="canonical byte budget"):
        validate_shield_v4_receipt_contract(
            flow["receipt"],
            expected_context_hash=flow["expected_context_hash"],
        )

    monkeypatch.setattr(contract_module, "MAX_CANONICAL_RECEIPT_BYTES", MAX_CANONICAL_RECEIPT_BYTES)
    monkeypatch.setattr(contract_module, "MAX_SIGNATURE_BUNDLE_BYTES", 1)
    with pytest.raises(ShieldV4ReceiptContractError, match="signature bundle exceeds"):
        validate_preflighted_shield_v4_receipt_integrity(checked)

    monkeypatch.setattr(
        contract_module,
        "MAX_SIGNATURE_BUNDLE_BYTES",
        MAX_SIGNATURE_BUNDLE_BYTES,
    )
    overcount = copy.deepcopy(flow["receipt"])
    overcount["signature_bundle"]["signatures"].extend(
        copy.deepcopy(overcount["signature_bundle"]["signatures"]),
    )
    assert len(overcount["signature_bundle"]["signatures"]) > MAX_SIGNATURES_PER_BUNDLE
    with pytest.raises(ShieldV4ReceiptContractError, match="signature count"):
        validate_shield_v4_receipt_contract(
            overcount,
            expected_context_hash=flow["expected_context_hash"],
        )

    wrong_signed_hash = copy.deepcopy(checked)
    wrong_signed_hash["signed_payload_hash"] = "0" * 64
    for entry in wrong_signed_hash["signature_bundle"]["signatures"]:
        entry["signed_payload_hash"] = "0" * 64
    with pytest.raises(ShieldV4ReceiptContractError, match="signed payload hash"):
        validate_preflighted_shield_v4_receipt_integrity(wrong_signed_hash)


def test_v410c_precondition_rejections_never_validate_claimed_audit_artifact() -> None:
    flow = _flow()
    common = {
        "expected_context_hash": flow["expected_context_hash"],
        "trusted_key_registry": flow["trusted_key_registry"],
        "verification_time": flow["verification_time"],
        "signature_verifier": _verify_test_only_signature,
    }
    capture = _TranscriptCapture()
    result = _verify_shield_v4_orchestrator_receipt(
        flow["receipt"],
        expected_request_id="",
        transcript_observer=capture,
        **common,
    )
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert capture.validated_artifact is None
    assert capture.contract_rejection_reason == verifier_module.V4_CONTRACT_INVALID

    capture = _TranscriptCapture()
    result = _verify_shield_v4_orchestrator_receipt(
        flow["receipt"],
        expected_context_hash="not-a-hash",
        expected_request_id=flow["expected_request_id"],
        transcript_observer=capture,
        **{key: value for key, value in common.items() if key != "expected_context_hash"},
    )
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert capture.validated_artifact is None
    assert capture.contract_rejection_reason == verifier_module.V4_CONTRACT_INVALID

    capture = _TranscriptCapture()
    result = _verify_shield_v4_orchestrator_receipt(
        flow["receipt"],
        expected_request_id=flow["expected_request_id"],
        verification_time="not-a-time",
        transcript_observer=capture,
        **{key: value for key, value in common.items() if key != "verification_time"},
    )
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW
    assert capture.validated_artifact is None
    assert capture.contract_rejection_reason == "V4_FRESHNESS_INVALID"

    with pytest.raises(_VerifierRejection, match="must end in Z"):
        verifier_module._parse_utc("2026-01-01T00:00:00+00:00", field="time")

    capture = _TranscriptCapture()
    result = _verify_shield_v4_orchestrator_receipt(
        flow["receipt"],
        expected_request_id=flow["expected_request_id"],
        minimum_key_registry_version=0,
        transcript_observer=capture,
        **common,
    )
    assert result.state is ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert capture.validated_artifact is None
    assert capture.contract_rejection_reason == verifier_module.V4_CONTRACT_INVALID


def test_v410c_external_scalars_reject_before_receipt_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    integrity_calls = _install_forbidden_integrity(monkeypatch)
    key_calls = 0
    backend_calls = 0

    def forbidden_key(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal key_calls
        key_calls += 1
        raise AssertionError("key lookup must not run")

    def forbidden_backend(_entry: Any, _key: Any) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        raise AssertionError("backend must not run")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key)
    common = {
        "receipt": flow["receipt"],
        "expected_context_hash": flow["expected_context_hash"],
        "expected_request_id": flow["expected_request_id"],
        "trusted_key_registry": flow["trusted_key_registry"],
        "verification_time": flow["verification_time"],
        "signature_verifier": forbidden_backend,
    }
    for overrides, expected_state in (
        (
            {"expected_context_hash": "a" * (MAX_TEXT_FIELD_BYTES + 1)},
            ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT,
        ),
        (
            {"expected_request_id": "r" * (MAX_TEXT_FIELD_BYTES + 1)},
            ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT,
        ),
        (
            {"expected_request_id": "   "},
            ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT,
        ),
        (
            {"verification_time": "2" * (MAX_TEXT_FIELD_BYTES + 1)},
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
        ),
        (
            {"minimum_key_registry_version": 1 << 63},
            ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT,
        ),
    ):
        params = dict(common)
        params.update(overrides)
        result = verify_shield_v4_orchestrator_receipt(**params)
        assert result.state is expected_state
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}
    assert key_calls == 0
    assert backend_calls == 0


def test_v410c_audited_external_scalars_fail_before_normalization_sink_or_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _flow()
    integrity_calls = _install_forbidden_integrity(monkeypatch)
    key_calls = 0
    backend_calls = 0

    def forbidden_key(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal key_calls
        key_calls += 1
        raise AssertionError("key lookup must not run")

    def forbidden_backend(_entry: Any, _key: Any) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        raise AssertionError("backend must not run")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key)
    common = {
        "receipt": flow["receipt"],
        "expected_context_hash": flow["expected_context_hash"],
        "expected_request_id": flow["expected_request_id"],
        "trusted_key_registry": flow["trusted_key_registry"],
        "verification_time": flow["verification_time"],
        "artifact_transport_hash": TRANSPORT_HASH,
        "signature_verifier": forbidden_backend,
    }
    cases = (
        {"expected_context_hash": "a" * (MAX_TEXT_FIELD_BYTES + 1)},
        {"expected_request_id": "r" * (MAX_TEXT_FIELD_BYTES + 1)},
        {"verification_time": "2" * (MAX_TEXT_FIELD_BYTES + 1)},
        {"artifact_transport_hash": "b" * (MAX_TEXT_FIELD_BYTES + 1)},
        {"minimum_key_registry_version": 1 << 63},
        {"minimum_key_registry_version": True},
        {"minimum_key_registry_version": 0},
    )
    for overrides in cases:
        sink = _Sink()
        params = dict(common)
        params.update(overrides)
        with pytest.raises(ValueError):
            verify_shield_v4_orchestrator_receipt_with_audit(
                audit_sink=sink,
                **params,
            )
        assert sink.records == ()

    class ForbiddenUnicodeData:
        @staticmethod
        def normalize(*_args: Any, **_kwargs: Any) -> str:
            raise AssertionError("normalization must not run")

    monkeypatch.setattr(audit_module, "unicodedata", ForbiddenUnicodeData)
    sink = _Sink()
    with pytest.raises(ValueError):
        verify_shield_v4_orchestrator_receipt_with_audit(
            audit_sink=sink,
            expected_request_id="r" * (MAX_TEXT_FIELD_BYTES + 1),
            **{key: value for key, value in common.items() if key != "expected_request_id"},
        )
    assert sink.records == ()
    assert integrity_calls == {"canonical": 0, "receipt_hash": 0, "signed_hash": 0}
    assert key_calls == 0
    assert backend_calls == 0


def test_v410c_audit_reason_policy_branch_and_bounded_snapshot_contract() -> None:
    assert verifier_module._audit_reason_for_contract_error(
        ShieldV4ReceiptContractError("signature bundle invalid"),
    ) == verifier_module.V4_POLICY_INVALID
    with pytest.raises(ShieldV4ReceiptContractError, match="structural work budget"):
        preflight_shield_v4_receipt_contract(
            {"cycle": None, "other": "x" * (MAX_TEXT_FIELD_BYTES + 1)},
            expected_context_hash="a" * 64,
        )


def test_v410c_benchmark_json_workflow_and_document_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_path = ROOT / "scripts" / "benchmark_shield_v410c_verification.py"
    spec = importlib.util.spec_from_file_location("shield_v410c_benchmark", script_path)
    assert spec is not None and spec.loader is not None
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    monkeypatch.setattr(
        benchmark,
        "_measure",
        lambda _operation: {"median_ms": 1.0, "p95_ms": 2.0},
    )
    monkeypatch.setattr(
        benchmark,
        "_software_versions",
        lambda: dict(benchmark.PINNED_SOFTWARE),
    )
    monkeypatch.setattr(benchmark.platform, "python_version", lambda: "3.11.15")
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    assert benchmark.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {
        "schema_version",
        "repository",
        "fixture_sha256",
        "environment",
        "software",
        "warmups",
        "samples",
        "valid",
        "oversize_rejection",
        "status",
    }
    assert output["schema_version"] == "shield-v4-v410c-performance-v1"
    assert output["repository"] == "DigiByte-AdamantineOS"
    assert output["fixture_sha256"] == (
        "b1031e999b87f61643748848e6d121f153c3cbdc7c87ceef9a62c766bc8b7ced"
    )
    assert benchmark.REQUIRED_FIXTURE_SHA256 == output["fixture_sha256"]
    assert set(output["environment"]) == {
        "python",
        "platform",
        "pythonhashseed",
        "tz",
        "lc_all",
    }
    assert output["software"] == {
        "pip": "25.2",
        "setuptools": "80.9.0",
        "wheel": "0.45.1",
        "pytest": "8.4.1",
        "pytest-cov": "6.2.1",
    }
    assert output["warmups"] == 20
    assert output["samples"] == 200
    assert output["valid"] == {
        "median_ms": 1.0,
        "p95_ms": 2.0,
        "limit_ms": 50.0,
    }
    assert output["oversize_rejection"] == {
        "median_ms": 1.0,
        "p95_ms": 2.0,
        "limit_ms": 20.0,
    }
    assert output["status"] == "PASS"

    workflow = (
        ROOT / ".github" / "workflows" / "shield-v4-performance-dos.yml"
    ).read_text(encoding="utf-8")
    assert "runs-on: ubuntu-24.04" in workflow
    assert 'python-version: "3.11.15"' in workflow
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38" in workflow
    assert 'PYTHONHASHSEED: "0"' in workflow
    assert 'TZ: "UTC"' in workflow
    assert 'LC_ALL: "C.UTF-8"' in workflow
    for pin in (
        "pip==25.2",
        "setuptools==80.9.0",
        "wheel==0.45.1",
        "pytest==8.4.1",
        "pytest-cov==6.2.1",
        "--no-build-isolation --no-deps -e .",
    ):
        assert pin in workflow
    assert "pytest-benchmark" not in workflow
    assert "benchmark_shield_v410c_verification.py" not in (
        ROOT / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")

    performance_contract = (
        ROOT / "docs" / "CONTRACTS" / "shield_v4_performance_dos_envelope_v1.md"
    ).read_text(encoding="utf-8")
    for phrase in (
        "parsed mapping plus a caller-supplied",
        "cannot claim a limit on the unavailable",
        "20 warmups and 200 measured iterations",
        "It excludes native provider latency",
        "b1031e999b87f61643748848e6d121f153c3cbdc7c87ceef9a62c766bc8b7ced",
        "AdamantineOS remains the final execution boundary",
    ):
        assert phrase in performance_contract
