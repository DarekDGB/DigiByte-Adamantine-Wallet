from __future__ import annotations

import copy
import hashlib
import hmac
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    receipt_hash,
    signed_payload_hash,
    unsigned_receipt_payload,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    ShieldV4ReceiptVerificationState,
    _verify_test_only_signature,
)
from adamantine.v1.integrations.shield_v4_verification_audit import (
    AUDIT_ACK_SCHEMA_VERSION,
    AUDIT_BATCH_HASH_DOMAIN,
    AUDIT_KEY_ID_HASH_DOMAIN,
    AUDIT_REQUEST_ID_HASH_DOMAIN,
    AUDIT_SCHEMA_VERSION,
    AUDIT_VERIFIER_ID,
    ArtifactVerificationAuditRecord,
    ShieldV4AuditSinkError,
    ShieldV4AuditedVerificationError,
    SignatureVerificationAuditRecord,
    VerificationPreflightAuditRecord,
    V4_BACKEND_FAILURE,
    V4_BACKEND_UNAVAILABLE,
    V4_AUTHORITY_BYPASS,
    V4_CONTRACT_INVALID,
    V4_CONTEXT_MISMATCH,
    V4_FRESHNESS_INVALID,
    V4_HASH_MISMATCH,
    V4_POLICY_INVALID,
    V4_REGISTRY_INVALID,
    V4_REPLAY_REJECTED,
    V4_REQUEST_MISMATCH,
    V4_DOWNGRADE_REJECTED,
    V4_SIGNATURE_INVALID,
    V4_VERIFY_OK,
    _canonical_batch_bytes,
    _canonical_record_bytes,
    _parse_audit_record,
    _record_dict,
    _validate_event,
    _validate_batch,
    audit_batch_sha256,
    audit_key_id_hash,
    audit_request_id_hash,
    serialize_audit_record,
    verify_shield_v4_orchestrator_receipt_with_audit,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "adamantine"
    / "v1"
    / "fixtures"
    / "shield_v4"
    / "full_multi_repo_v4_allow_flow.json"
)
TRANSPORT_HASH = "b" * 64


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _resign_test_only_component(component: dict[str, Any]) -> None:
    unsigned = {
        key: component[key]
        for key in component
        if key not in {"signed_payload_hash", "signature_bundle", "verification_summary"}
    }
    payload_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=unsigned)
    prefix = {
        "adn": "TEST-ONLY-ADN-SIGNATURE",
        "dqsn": "TEST-ONLY-DQSN-SIGNATURE",
        "guardian_wallet": "TEST-ONLY-GUARDIAN-WALLET-SIGNATURE",
        "qwg": "TEST-ONLY-QWG-SIGNATURE",
        "sentinel_ai": "TEST-ONLY-SENTINEL-AI-SIGNATURE",
    }[component["component_id"]]
    component["signed_payload_hash"] = payload_hash
    for entry in component["signature_bundle"]["signatures"]:
        entry["signed_payload_hash"] = payload_hash
        public_key = f"TEST-ONLY-PUBLIC-shield_component_{component['component_id']}-{entry['algorithm']}-v1"
        entry["signature"] = hashlib.sha256(
            f"{prefix}\n{public_key}\n{entry['algorithm']}\n{entry['standard_profile']}\n{payload_hash}".encode()
        ).hexdigest()


def _resign_test_only_receipt(receipt: dict[str, Any]) -> None:
    unsigned = unsigned_receipt_payload(receipt)
    receipt["receipt_hash"] = receipt_hash(unsigned)
    payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned)
    receipt["signed_payload_hash"] = payload_hash
    for entry in receipt["signature_bundle"]["signatures"]:
        entry["signed_payload_hash"] = payload_hash
        public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{entry['algorithm']}-v1"
        material = (
            f"{entry['domain_tag']}|{payload_hash}|{entry['algorithm']}|"
            f"{entry['standard_profile']}|{entry['key_id']}|{entry['key_version']}"
        )
        entry["signature"] = hmac.new(public_key.encode(), material.encode(), "sha256").hexdigest()


class RecordingSink:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, ...]] = []

    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        assert all(type(record) is bytes for record in records)
        self.calls.append(records)
        return {
            "schema_version": AUDIT_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


def _decode(records: tuple[bytes, ...]) -> list[dict[str, Any]]:
    return [json.loads(record.decode("utf-8")) for record in records]


def _verify(
    fixture: dict[str, Any],
    *,
    sink: Any | None = None,
    receipt: Any | None = None,
    signature_verifier: Any = _verify_test_only_signature,
    **overrides: Any,
):
    target_sink = sink or RecordingSink()
    params = {
        "expected_context_hash": fixture["expected_context_hash"],
        "expected_request_id": fixture["expected_request_id"],
        "trusted_key_registry": fixture["trusted_key_registry"],
        "verification_time": fixture["verification_time"],
        "audit_sink": target_sink,
        "artifact_transport_hash": TRANSPORT_HASH,
        "signature_verifier": signature_verifier,
    }
    params.update(overrides)
    result = verify_shield_v4_orchestrator_receipt_with_audit(
        fixture["receipt"] if receipt is None else receipt,
        **params,
    )
    return result, target_sink


def test_v410b_success_is_returned_only_after_exact_atomic_audit_ack() -> None:
    fixture = _fixture()
    result, sink = _verify(fixture)

    assert result.state is ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert result.accepted_as_evidence is True
    assert result.final_approval is False
    assert len(sink.calls) == 1
    record_bytes = sink.calls[0]
    records = _decode(record_bytes)
    assert len(records) == 14
    assert records[0] == {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "event_type": "verification_preflight",
        "verifier_id": AUDIT_VERIFIER_ID,
        "verification_timestamp": fixture["verification_time"],
        "verification_passed": True,
        "reason_id": V4_VERIFY_OK,
        "artifact_type": "orchestrator_receipt",
        "expected_artifact_schema_version": "shield.receipt.v2",
        "artifact_transport_hash": TRANSPORT_HASH,
        "expected_request_id_hash": audit_request_id_hash(fixture["expected_request_id"]),
        "expected_context_hash": fixture["expected_context_hash"],
        "required_policy_version": "policy.v1",
        "minimum_registry_version": 1,
    }
    signatures = records[1:-1]
    assert all(record["event_type"] == "signature_verification" for record in signatures)
    assert [record["artifact_id"] for record in signatures] == [
        "adn",
        "adn",
        "dqsn",
        "dqsn",
        "guardian_wallet",
        "guardian_wallet",
        "qwg",
        "qwg",
        "sentinel_ai",
        "sentinel_ai",
        "shield_orchestrator",
        "shield_orchestrator",
    ]
    assert all(record["reason_id"] == V4_VERIFY_OK for record in signatures)
    terminal = records[-1]
    assert terminal["event_type"] == "artifact_verification"
    assert terminal["verification_passed"] is True
    assert terminal["reason_id"] == V4_VERIFY_OK
    assert terminal["artifact_hash"] == fixture["receipt"]["signed_payload_hash"]


def test_v410b_identifier_hashes_are_domain_separated_nfc_and_never_raw() -> None:
    decomposed = "reque\u0301st-secret"
    normalized = unicodedata.normalize("NFC", decomposed)
    request_hash = audit_request_id_hash(decomposed)
    key_hash = audit_key_id_hash(decomposed)

    assert request_hash == hashlib.sha256(
        AUDIT_REQUEST_ID_HASH_DOMAIN.encode() + normalized.encode()
    ).hexdigest()
    assert key_hash == hashlib.sha256(
        AUDIT_KEY_ID_HASH_DOMAIN.encode() + normalized.encode()
    ).hexdigest()
    assert request_hash != key_hash
    with pytest.raises(ValueError, match="request_id must be non-empty"):
        audit_request_id_hash("")
    with pytest.raises(ValueError, match="key_id must be non-empty"):
        audit_key_id_hash("")


def test_v410b_batch_hash_binds_domain_exact_array_and_order() -> None:
    fixture = _fixture()
    _, sink = _verify(fixture)
    records = sink.calls[0]
    expected = hashlib.sha256(
        AUDIT_BATCH_HASH_DOMAIN.encode("utf-8") + _canonical_batch_bytes(records)
    ).hexdigest()
    assert audit_batch_sha256(records) == expected
    assert audit_batch_sha256(tuple(reversed(records))) != expected
    assert len(records[0]) <= 2048


def test_v410b_cross_repo_canonical_sample_and_batch_hash_lock() -> None:
    record = VerificationPreflightAuditRecord(
        AUDIT_SCHEMA_VERSION,
        "verification_preflight",
        AUDIT_VERIFIER_ID,
        "2026-06-21T00:02:00Z",
        True,
        V4_VERIFY_OK,
        "orchestrator_receipt",
        "shield.receipt.v2",
        "b" * 64,
        audit_request_id_hash("shared-request"),
        "a" * 64,
        "policy.v1",
        1,
    )
    encoded = serialize_audit_record(record)
    assert encoded == (
        b'{"artifact_transport_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'"artifact_type":"orchestrator_receipt","event_type":"verification_preflight",'
        b'"expected_artifact_schema_version":"shield.receipt.v2",'
        b'"expected_context_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"expected_request_id_hash":"527303d8de3a78e84a3574dba02610a1e6f9d21d5a7326c40f5bafd22895e1f5",'
        b'"minimum_registry_version":1,"reason_id":"V4_VERIFY_OK",'
        b'"required_policy_version":"policy.v1","schema_version":"shield.verification_audit.v1",'
        b'"verification_passed":true,"verification_timestamp":"2026-06-21T00:02:00Z",'
        b'"verifier_id":"adamantineos.v1"}'
    )
    assert audit_batch_sha256((encoded,)) == (
        "e71d1f33a9c85b81b06566e2dd009acae5755874e4ae7a93d5a107a11c7567f3"
    )
    assert _canonical_record_bytes(record) == encoded


@pytest.mark.parametrize(
    ("mutation", "reason", "state"),
    [
        (lambda r: r.update({"schema_version": "bad"}), V4_CONTRACT_INVALID, ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT),
        (lambda r: r.update({"context_hash": "c" * 64}), V4_CONTEXT_MISMATCH, ShieldV4ReceiptVerificationState.REJECTED_CONTEXT_MISMATCH),
        (lambda r: r.update({"receipt_hash": "d" * 64}), V4_HASH_MISMATCH, ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT),
        (lambda r: r["signature_bundle"].update({"policy_version": "policy.v0"}), V4_POLICY_INVALID, ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT),
        (lambda r: r.update({"schema_version": "shield.receipt.v1"}), V4_DOWNGRADE_REJECTED, ShieldV4ReceiptVerificationState.REJECTED_DOWNGRADE),
        (lambda r: r["adamantineos_handoff"].update({"final_approval": True}), V4_AUTHORITY_BYPASS, ShieldV4ReceiptVerificationState.REJECTED_AUTHORITY_BYPASS),
    ],
)
def test_v410b_failure_paths_are_audited_without_untrusted_payload_fields(
    mutation: Any,
    reason: str,
    state: ShieldV4ReceiptVerificationState,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    mutation(receipt)
    result, sink = _verify(fixture, receipt=receipt)

    assert result.state is state
    assert result.accepted_as_evidence is False
    assert len(sink.calls) == 1
    events = _decode(sink.calls[0])
    assert events[0]["verification_passed"] is False
    assert events[0]["reason_id"] == reason
    serialized = _canonical_batch_bytes(sink.calls[0]).decode("utf-8")
    assert fixture["expected_request_id"] not in serialized
    assert '"signature"' not in serialized
    assert '"metadata"' not in serialized
    assert '"public_key"' not in serialized


def test_v410b_validated_request_registry_freshness_and_replay_rejections_have_terminal() -> None:
    fixture = _fixture()
    cases = (
        ({"expected_request_id": "wrong-request"}, V4_REQUEST_MISMATCH),
        ({"minimum_key_registry_version": 2}, V4_REGISTRY_INVALID),
        ({"verification_time": "2026-06-22T00:02:00Z"}, V4_FRESHNESS_INVALID),
        ({"seen_request_ids": (fixture["expected_request_id"],)}, V4_REPLAY_REJECTED),
    )
    for overrides, reason in cases:
        result, sink = _verify(fixture, **overrides)
        assert result.accepted_as_evidence is False
        events = _decode(sink.calls[0])
        assert events[0]["reason_id"] == V4_VERIFY_OK
        assert events[-1]["reason_id"] == reason
        assert events[-1]["verification_passed"] is False


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (None, V4_BACKEND_UNAVAILABLE),
        (lambda _entry, _key: False, V4_SIGNATURE_INVALID),
        (lambda _entry, _key: "true", V4_BACKEND_FAILURE),
    ],
)
def test_v410b_backend_rejections_use_only_stable_allowlisted_reasons(
    backend: Any,
    reason: str,
) -> None:
    fixture = _fixture()
    result, sink = _verify(fixture, signature_verifier=backend)
    assert result.accepted_as_evidence is False
    events = _decode(sink.calls[0])
    assert events[-1]["reason_id"] == reason
    if backend is not None:
        assert events[-2]["reason_id"] == reason


def test_v410b_backend_exception_text_is_not_logged_or_chained() -> None:
    fixture = _fixture()

    def backend(_entry: Any, _key: Any) -> bool:
        raise RuntimeError("PRIVATE seed raw-signature secret")

    result, sink = _verify(fixture, signature_verifier=backend)
    assert result.accepted_as_evidence is False
    assert _decode(sink.calls[0])[-2]["reason_id"] == V4_BACKEND_FAILURE
    assert "PRIVATE" not in _canonical_batch_bytes(sink.calls[0]).decode()


class BadSink:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    def append_batch(self, records: tuple[Any, ...]) -> Any:
        if self.mode == "raise":
            raise RuntimeError("secret sink details")
        ack: dict[str, Any] = {
            "schema_version": AUDIT_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }
        if self.mode == "type":
            class HostileAck(dict):
                def __iter__(self):
                    raise RuntimeError("SECRET-ACK-ITER")

            return HostileAck(ack)
        if self.mode == "key-subclass":
            class AckKey(str):
                pass

            return {AckKey(key): value for key, value in ack.items()}
        if self.mode == "missing":
            del ack["batch_sha256"]
            return ack
        if self.mode == "extra":
            ack["extra"] = "forbidden"
            return ack
        if self.mode == "schema":
            ack["schema_version"] = "bad"
            return ack
        if self.mode == "hash":
            ack["batch_sha256"] = "0" * 64
            return ack
        if self.mode == "hash-type":
            ack["batch_sha256"] = b"0" * 64
            return ack
        if self.mode == "count":
            ack["record_count"] = len(records) + 1
            return ack
        if self.mode == "bool-count":
            ack["record_count"] = True
            return ack
        ack["durably_committed"] = False
        return ack


@pytest.mark.parametrize(
    "mode",
    (
        "raise",
        "type",
        "key-subclass",
        "missing",
        "extra",
        "schema",
        "hash",
        "hash-type",
        "count",
        "bool-count",
        "durable",
    ),
)
def test_v410b_sink_or_ack_failure_never_returns_evidence_and_has_no_cause(mode: str) -> None:
    fixture = _fixture()
    with pytest.raises(ShieldV4AuditSinkError, match="^V4_AUDIT_SINK_FAILURE$") as raised:
        _verify(fixture, sink=BadSink(mode))
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"verification_time": "2026-06-21T00:02:00.000Z"}, "exact-second"),
        ({"verification_time": "2026-02-30T00:02:00Z"}, "exact-second"),
        ({"expected_context_hash": "A" * 64}, "expected_context_hash"),
        ({"artifact_transport_hash": "not-a-hash"}, "artifact_transport_hash"),
        ({"expected_request_id": ""}, "request_id"),
        ({"minimum_key_registry_version": True}, "minimum_key_registry_version"),
    ],
)
def test_v410b_invalid_trusted_preflight_input_stops_before_sink(
    overrides: dict[str, Any],
    message: str,
) -> None:
    fixture = _fixture()
    sink = RecordingSink()
    with pytest.raises(ValueError, match=message):
        _verify(fixture, sink=sink, **overrides)
    assert sink.calls == []


def test_v410b_batch_limits_and_exact_record_union_reject_invalid_inputs(monkeypatch: Any) -> None:
    fixture = _fixture()
    _, sink = _verify(fixture)
    valid = sink.calls[0]
    with pytest.raises(ValueError, match="record count"):
        _validate_batch(())
    with pytest.raises(ValueError, match="record count"):
        _validate_batch(tuple(valid[0] for _ in range(25)))
    with pytest.raises(ValueError, match="immutable bytes"):
        _validate_batch((object(),))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="byte length"):
        _validate_batch((b"x" * 2049,))
    monkeypatch.setattr(
        "adamantine.v1.integrations.shield_v4_verification_audit.MAX_AUDIT_BATCH_BYTES",
        len(_canonical_batch_bytes(valid)) - 1,
    )
    with pytest.raises(ValueError, match="batch exceeds"):
        _validate_batch(valid)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "bad", "schema"),
        ("event_type", "bad", "event_type"),
        ("verifier_id", "bad", "verifier"),
        ("reason_id", "bad", "reason_id"),
        ("verification_timestamp", "2026-06-21T00:02:00.0Z", "exact-second"),
        ("verification_passed", 1, "exact bool"),
        ("artifact_hash", "A" * 64, "artifact_hash"),
        ("registry_version", True, "positive integer"),
        ("artifact_id", "unknown", "artifact_id"),
        ("artifact_type", "payload", "artifact_type"),
        ("standard_profile", "draft-profile", "standard_profile"),
    ],
)
def test_v410b_signature_record_validator_rejects_adversarial_field_semantics(
    field: str,
    value: Any,
    message: str,
) -> None:
    fixture = _fixture()
    _, sink = _verify(fixture)
    event = _decode(sink.calls[0])[1]
    event[field] = value
    with pytest.raises(ValueError, match=message):
        _validate_event(event)


def test_v410b_record_parser_rejects_noncanonical_and_duplicate_json() -> None:
    fixture = _fixture()
    _, sink = _verify(fixture)
    canonical = sink.calls[0][0]
    with pytest.raises(ValueError, match="exact canonical bytes"):
        _parse_audit_record(b" " + canonical)
    duplicate = canonical[:-1] + b',"schema_version":"shield.verification_audit.v1"}'
    with pytest.raises(ValueError, match="exact canonical bytes"):
        _parse_audit_record(duplicate)


def test_v410b_validator_covers_every_exact_union_boundary(monkeypatch: Any) -> None:
    fixture = _fixture()
    _, sink = _verify(fixture)
    preflight, signature, terminal = _decode(sink.calls[0])[0], _decode(sink.calls[0])[1], _decode(sink.calls[0])[-1]

    with pytest.raises(ValueError, match="unsupported record"):
        _record_dict(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="object"):
        _validate_event([])

    mutations = (
        (preflight, {"extra": True}, "preflight event fields"),
        (preflight, {"artifact_type": "component_verdict"}, "preflight artifact_type"),
        (preflight, {"expected_artifact_schema_version": "bad"}, "preflight expected schema"),
        (preflight, {"required_policy_version": "bad"}, "preflight policy"),
        (signature, {"extra": True}, "signature event fields"),
        (signature, {"artifact_schema_version": "bad"}, "artifact schema"),
        (signature, {"policy_version": "bad"}, "audit policy"),
        (signature, {"algorithm": "unknown"}, "algorithm"),
        (terminal, {"extra": True}, "artifact event fields"),
        (terminal, {"artifact_id": "unknown"}, "receipt audit artifact_id"),
        (terminal, {"reason_id": V4_CONTRACT_INVALID}, "pass and reason"),
    )
    for original, updates, message in mutations:
        event = dict(original)
        event.update(updates)
        with pytest.raises(ValueError, match=message):
            _validate_event(event)

    record = VerificationPreflightAuditRecord(**preflight)
    monkeypatch.setattr(
        "adamantine.v1.integrations.shield_v4_verification_audit.MAX_AUDIT_RECORD_BYTES",
        len(serialize_audit_record(record)) - 1,
    )
    with pytest.raises(ValueError, match="record exceeds"):
        serialize_audit_record(record)

    with pytest.raises(ValueError, match="canonical UTF-8 JSON"):
        _parse_audit_record(b"\xff")
    with pytest.raises(ValueError, match="canonical UTF-8 JSON"):
        _parse_audit_record(b"{")


def test_v410b_component_request_ids_are_hashed_per_artifact() -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    component = receipt["component_verdicts"][0]
    component["request_id"] = "component-private-request"
    _resign_test_only_component(component)
    _resign_test_only_receipt(receipt)
    result, sink = _verify(fixture, receipt=receipt)
    assert result.accepted_as_evidence is True
    adn_records = [
        record
        for record in _decode(sink.calls[0])
        if record["event_type"] == "signature_verification" and record["artifact_id"] == "adn"
    ]
    assert {record["request_id_hash"] for record in adn_records} == {
        audit_request_id_hash("component-private-request")
    }
    assert adn_records[0]["request_id_hash"] != audit_request_id_hash(fixture["expected_request_id"])
    assert "component-private-request" not in _canonical_batch_bytes(sink.calls[0]).decode()


@pytest.mark.parametrize("hostile_kind", ("get", "items", "iter", "nested-list"))
def test_v410b_hostile_receipt_operation_is_sanitized_and_audited(hostile_kind: str) -> None:
    fixture = _fixture()

    class HostileDict(dict):
        def get(self, *args: Any, **kwargs: Any) -> Any:
            if hostile_kind == "get":
                raise RuntimeError("SECRET-get")
            return super().get(*args, **kwargs)

        def items(self):
            if hostile_kind == "items":
                raise RuntimeError("SECRET-items")
            return super().items()

        def __iter__(self):
            if hostile_kind == "iter":
                raise RuntimeError("SECRET-iter")
            return super().__iter__()

    class HostileList(list):
        def __iter__(self):
            raise RuntimeError("SECRET-nested-list")

    receipt: Any = HostileDict(copy.deepcopy(fixture["receipt"]))
    if hostile_kind == "nested-list":
        receipt["component_verdicts"] = HostileList(receipt["component_verdicts"])
    sink = RecordingSink()
    with pytest.raises(
        ShieldV4AuditedVerificationError,
        match="^V4_CONTRACT_INVALID$",
    ) as raised:
        _verify(fixture, receipt=receipt, sink=sink)
    assert raised.value.__cause__ is None
    assert "SECRET" not in str(raised.value)
    assert len(sink.calls) == 1
    events = _decode(sink.calls[0])
    assert len(events) == 1
    assert events[0]["event_type"] == "verification_preflight"
    assert events[0]["verification_passed"] is False
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert b"SECRET" not in sink.calls[0][0]


@pytest.mark.parametrize("inconsistency", ("keys", "get"))
def test_v410b_mutating_receipt_snapshot_is_sanitized_and_audited(inconsistency: str) -> None:
    fixture = _fixture()

    class MutatingDict(dict):
        def __iter__(self):
            values = tuple(super().__iter__())
            return iter(values[:-1] if inconsistency == "keys" else values)

        def get(self, key: Any, default: Any = None) -> Any:
            if inconsistency == "get" and key == "schema_version":
                return default
            return super().get(key, default)

    sink = RecordingSink()
    with pytest.raises(ShieldV4AuditedVerificationError, match="^V4_CONTRACT_INVALID$"):
        _verify(fixture, receipt=MutatingDict(copy.deepcopy(fixture["receipt"])), sink=sink)
    assert len(sink.calls) == 1
    assert _decode(sink.calls[0])[0]["reason_id"] == V4_CONTRACT_INVALID


@pytest.mark.parametrize("scalar_kind", ("string-value", "integer-value", "string-key", "float"))
def test_v410b_non_exact_or_non_json_scalar_is_sanitized_and_audited(
    scalar_kind: str,
) -> None:
    fixture = _fixture()

    class EvilStr(str):
        pass

    class EvilInt(int):
        pass

    receipt = copy.deepcopy(fixture["receipt"])
    if scalar_kind == "string-value":
        receipt["schema_version"] = EvilStr(receipt["schema_version"])
    elif scalar_kind == "integer-value":
        receipt["key_registry_version"] = EvilInt(receipt["key_registry_version"])
    elif scalar_kind == "string-key":
        receipt[EvilStr("forbidden_key")] = "value"
    else:
        receipt["forbidden_float"] = 1.0

    sink = RecordingSink()
    with pytest.raises(
        ShieldV4AuditedVerificationError,
        match="^V4_CONTRACT_INVALID$",
    ) as raised:
        _verify(fixture, receipt=receipt, sink=sink)
    assert raised.value.__cause__ is None
    assert len(sink.calls) == 1
    events = _decode(sink.calls[0])
    assert len(events) == 1
    assert events[0]["event_type"] == "verification_preflight"
    assert events[0]["verification_passed"] is False
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
