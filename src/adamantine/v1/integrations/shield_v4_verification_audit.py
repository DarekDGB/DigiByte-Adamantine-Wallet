from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol, TypeAlias

from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    ALGORITHM_STANDARD_PROFILES,
    COMPONENT_ROLES,
    RECEIPT_SCHEMA_VERSION,
    SIGNATURE_POLICY,
    VERDICT_SCHEMA_VERSION,
    to_canonical_json,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    ShieldV4ReceiptVerificationResult,
    ShieldV4ReceiptVerificationState,
    SignatureVerifier,
    _SignatureVerificationObservation,
    _VerificationArtifactIdentity,
    _VerificationTranscriptObserver,
    _verify_shield_v4_orchestrator_receipt,
)
from adamantine.v1.integrations.shield_v4_work_budget import (
    ShieldV4WorkBudgetError,
    bounded_json_snapshot,
    require_bounded_text,
    require_signed_integer,
)

AUDIT_SCHEMA_VERSION = "shield.verification_audit.v1"
AUDIT_ACK_SCHEMA_VERSION = "shield.verification_audit.append_ack.v1"
AUDIT_VERIFIER_ID = "adamantineos.v1"
AUDIT_REQUEST_ID_HASH_DOMAIN = "DGB-SHIELD-V4-AUDIT-REQUEST-ID\n"
AUDIT_KEY_ID_HASH_DOMAIN = "DGB-SHIELD-V4-AUDIT-KEY-ID\n"
AUDIT_BATCH_HASH_DOMAIN = "DGB-SHIELD-V4-VERIFICATION-AUDIT-BATCH:shield.verification_audit.v1\n"

V4_VERIFY_OK = "V4_VERIFY_OK"
V4_CONTRACT_INVALID = "V4_CONTRACT_INVALID"
V4_CONTEXT_MISMATCH = "V4_CONTEXT_MISMATCH"
V4_REQUEST_MISMATCH = "V4_REQUEST_MISMATCH"
V4_HASH_MISMATCH = "V4_HASH_MISMATCH"
V4_DOWNGRADE_REJECTED = "V4_DOWNGRADE_REJECTED"
V4_AUTHORITY_BYPASS = "V4_AUTHORITY_BYPASS"
V4_POLICY_INVALID = "V4_POLICY_INVALID"
V4_REGISTRY_INVALID = "V4_REGISTRY_INVALID"
V4_FRESHNESS_INVALID = "V4_FRESHNESS_INVALID"
V4_REPLAY_REJECTED = "V4_REPLAY_REJECTED"
V4_SIGNATURE_INVALID = "V4_SIGNATURE_INVALID"
V4_BACKEND_UNAVAILABLE = "V4_BACKEND_UNAVAILABLE"
V4_BACKEND_FAILURE = "V4_BACKEND_FAILURE"

AUDIT_REASON_IDS = frozenset(
    {
        V4_VERIFY_OK,
        V4_CONTRACT_INVALID,
        V4_CONTEXT_MISMATCH,
        V4_REQUEST_MISMATCH,
        V4_HASH_MISMATCH,
        V4_DOWNGRADE_REJECTED,
        V4_AUTHORITY_BYPASS,
        V4_POLICY_INVALID,
        V4_REGISTRY_INVALID,
        V4_FRESHNESS_INVALID,
        V4_REPLAY_REJECTED,
        V4_SIGNATURE_INVALID,
        V4_BACKEND_UNAVAILABLE,
        V4_BACKEND_FAILURE,
    }
)

MAX_AUDIT_RECORDS = 24
MAX_AUDIT_RECORD_BYTES = 2048
MAX_AUDIT_BATCH_BYTES = 49152
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_EXACT_UTC_SECOND_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
COMMON_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "verifier_id",
        "verification_timestamp",
        "verification_passed",
        "reason_id",
    }
)
PREFLIGHT_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "expected_artifact_schema_version",
    "artifact_transport_hash",
    "expected_request_id_hash",
    "expected_context_hash",
    "required_policy_version",
    "minimum_registry_version",
}
SIGNATURE_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "artifact_schema_version",
    "artifact_id",
    "artifact_hash",
    "request_id_hash",
    "context_hash",
    "policy_version",
    "registry_version",
    "key_id_hash",
    "key_version",
    "algorithm",
    "standard_profile",
}
ARTIFACT_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "artifact_schema_version",
    "artifact_id",
    "artifact_hash",
    "request_id_hash",
    "context_hash",
    "policy_version",
    "registry_version",
}


@dataclass(frozen=True, slots=True)
class VerificationPreflightAuditRecord:
    schema_version: str
    event_type: str
    verifier_id: str
    verification_timestamp: str
    verification_passed: bool
    reason_id: str
    artifact_type: str
    expected_artifact_schema_version: str
    artifact_transport_hash: str
    expected_request_id_hash: str
    expected_context_hash: str
    required_policy_version: str
    minimum_registry_version: int


@dataclass(frozen=True, slots=True)
class SignatureVerificationAuditRecord:
    schema_version: str
    event_type: str
    verifier_id: str
    verification_timestamp: str
    verification_passed: bool
    reason_id: str
    artifact_type: str
    artifact_schema_version: str
    artifact_id: str
    artifact_hash: str
    request_id_hash: str
    context_hash: str
    policy_version: str
    registry_version: int
    key_id_hash: str
    key_version: int
    algorithm: str
    standard_profile: str


@dataclass(frozen=True, slots=True)
class ArtifactVerificationAuditRecord:
    schema_version: str
    event_type: str
    verifier_id: str
    verification_timestamp: str
    verification_passed: bool
    reason_id: str
    artifact_type: str
    artifact_schema_version: str
    artifact_id: str
    artifact_hash: str
    request_id_hash: str
    context_hash: str
    policy_version: str
    registry_version: int


VerificationAuditRecord: TypeAlias = (
    VerificationPreflightAuditRecord
    | SignatureVerificationAuditRecord
    | ArtifactVerificationAuditRecord
)
VerificationAuditRecordBytes: TypeAlias = bytes
AUDIT_ACK_FIELDS = frozenset(
    {
        "schema_version",
        "batch_sha256",
        "record_count",
        "durably_committed",
    }
)


class ShieldV4VerificationAuditSink(Protocol):
    """Append a complete verification transcript atomically or raise."""

    def append_batch(
        self,
        records: tuple[VerificationAuditRecordBytes, ...],
    ) -> dict[str, Any]:
        ...


class ShieldV4AuditSinkError(RuntimeError):
    """Durable audit evidence was not acknowledged; no evidence result escapes."""


class ShieldV4AuditedVerificationError(ValueError):
    """Receipt-controlled operation failed behind a sanitized audited barrier."""


def _identifier_hash(*, domain: str, value: str, field: str) -> str:
    try:
        value = require_bounded_text(value, field_name=field)
    except ShieldV4WorkBudgetError:
        raise ValueError(f"{field} must be non-empty string") from None
    normalized = unicodedata.normalize("NFC", value)
    return hashlib.sha256(domain.encode("utf-8") + normalized.encode("utf-8")).hexdigest()


def audit_request_id_hash(request_id: str) -> str:
    return _identifier_hash(
        domain=AUDIT_REQUEST_ID_HASH_DOMAIN,
        value=request_id,
        field="request_id",
    )


def audit_key_id_hash(key_id: str) -> str:
    return _identifier_hash(
        domain=AUDIT_KEY_ID_HASH_DOMAIN,
        value=key_id,
        field="key_id",
    )


def _record_dict(record: VerificationAuditRecord) -> dict[str, Any]:
    if type(record) not in {
        VerificationPreflightAuditRecord,
        SignatureVerificationAuditRecord,
        ArtifactVerificationAuditRecord,
    }:
        raise ValueError("audit batch contains unsupported record")
    return asdict(record)


def _validate_positive_int(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


def _validate_common(event: dict[str, Any]) -> None:
    if event.get("schema_version") != AUDIT_SCHEMA_VERSION:
        raise ValueError("audit event schema mismatch")
    if event.get("verifier_id") != AUDIT_VERIFIER_ID:
        raise ValueError("audit verifier mismatch")
    _validate_timestamp(event.get("verification_timestamp"))
    if type(event.get("verification_passed")) is not bool:
        raise ValueError("verification_passed must be exact bool")
    reason = event.get("reason_id")
    if reason not in AUDIT_REASON_IDS:
        raise ValueError("audit record reason_id outside allowlist")
    if (reason == V4_VERIFY_OK) is not event["verification_passed"]:
        raise ValueError("audit pass and reason semantics mismatch")


def _validate_artifact(event: dict[str, Any], *, signature: bool) -> None:
    artifact_type = event.get("artifact_type")
    if artifact_type not in {"component_verdict", "orchestrator_receipt"}:
        raise ValueError("unsupported audit artifact_type")
    expected_schema = (
        VERDICT_SCHEMA_VERSION if artifact_type == "component_verdict" else RECEIPT_SCHEMA_VERSION
    )
    if event.get("artifact_schema_version") != expected_schema:
        raise ValueError("audit artifact schema mismatch")
    artifact_id = event.get("artifact_id")
    if artifact_type == "component_verdict" and artifact_id not in COMPONENT_ROLES:
        raise ValueError("component audit artifact_id mismatch")
    if artifact_type == "orchestrator_receipt" and artifact_id != "shield_orchestrator":
        raise ValueError("receipt audit artifact_id mismatch")
    for field in ("artifact_hash", "request_id_hash", "context_hash"):
        _validate_sha256(event.get(field), field=field)
    if event.get("policy_version") != SIGNATURE_POLICY:
        raise ValueError("audit policy mismatch")
    _validate_positive_int(event.get("registry_version"), field="registry_version")
    if signature:
        _validate_sha256(event.get("key_id_hash"), field="key_id_hash")
        _validate_positive_int(event.get("key_version"), field="key_version")
        algorithm = event.get("algorithm")
        profile = event.get("standard_profile")
        if algorithm not in ALGORITHM_STANDARD_PROFILES:
            raise ValueError("unsupported audit algorithm")
        if profile not in ALGORITHM_STANDARD_PROFILES[algorithm]:
            raise ValueError("unsupported audit standard_profile")


def _validate_event(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("audit event must be object")
    event_type = event.get("event_type")
    if event_type == "verification_preflight":
        if set(event) != PREFLIGHT_FIELDS:
            raise ValueError("preflight event fields must match exact schema")
        _validate_common(event)
        if event["artifact_type"] != "orchestrator_receipt":
            raise ValueError("preflight artifact_type mismatch")
        if event["expected_artifact_schema_version"] != RECEIPT_SCHEMA_VERSION:
            raise ValueError("preflight expected schema mismatch")
        for field in ("artifact_transport_hash", "expected_request_id_hash", "expected_context_hash"):
            _validate_sha256(event[field], field=field)
        if event["required_policy_version"] != SIGNATURE_POLICY:
            raise ValueError("preflight policy mismatch")
        _validate_positive_int(event["minimum_registry_version"], field="minimum_registry_version")
        return event
    if event_type == "signature_verification":
        if set(event) != SIGNATURE_FIELDS:
            raise ValueError("signature event fields must match exact schema")
        _validate_common(event)
        _validate_artifact(event, signature=True)
        return event
    if event_type == "artifact_verification":
        if set(event) != ARTIFACT_FIELDS:
            raise ValueError("artifact event fields must match exact schema")
        _validate_common(event)
        _validate_artifact(event, signature=False)
        return event
    raise ValueError("unsupported audit event_type")


def serialize_audit_record(record: VerificationAuditRecord) -> VerificationAuditRecordBytes:
    event = _record_dict(record)
    _validate_event(event)
    encoded = to_canonical_json(event).encode("utf-8")
    if len(encoded) > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("audit record exceeds byte limit")
    return encoded


def _canonical_record_bytes(record: VerificationAuditRecord) -> bytes:
    return serialize_audit_record(record)


def _parse_audit_record(record: VerificationAuditRecordBytes) -> dict[str, Any]:
    if type(record) is not bytes:
        raise ValueError("audit record must be immutable bytes")
    if not record or len(record) > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("audit record byte length is invalid")
    try:
        event = json.loads(record.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("audit record must be canonical UTF-8 JSON") from exc
    _validate_event(event)
    if to_canonical_json(event).encode("utf-8") != record:
        raise ValueError("audit record must use exact canonical bytes")
    return event


def _canonical_batch_bytes(records: tuple[VerificationAuditRecordBytes, ...]) -> bytes:
    if type(records) is not tuple or not records or len(records) > MAX_AUDIT_RECORDS:
        raise ValueError("audit batch record count outside contract")
    events = [_parse_audit_record(record) for record in records]
    encoded = to_canonical_json({"records": events}).encode("utf-8")
    if len(encoded) > MAX_AUDIT_BATCH_BYTES:
        raise ValueError("audit batch exceeds byte limit")
    return encoded


def audit_batch_sha256(records: tuple[VerificationAuditRecordBytes, ...]) -> str:
    material = AUDIT_BATCH_HASH_DOMAIN.encode("ascii") + _canonical_batch_bytes(records)
    return hashlib.sha256(material).hexdigest()


def _validate_sha256(value: Any, *, field: str) -> str:
    if type(value) is not str or len(value) != 64 or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be lowercase sha256 hex")
    return value


def _validate_timestamp(value: Any) -> str:
    if type(value) is not str or len(value) != 20 or _EXACT_UTC_SECOND_RE.fullmatch(value) is None:
        raise ValueError("verification_time must be exact-second RFC3339 UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("verification_time must be exact-second RFC3339 UTC") from exc
    return value


def _validate_batch(records: tuple[VerificationAuditRecordBytes, ...]) -> None:
    _canonical_batch_bytes(records)


def _snapshot_untrusted_receipt(value: Any) -> Any:
    """Take the shared bounded exact-JSON snapshot before audit verification."""

    return bounded_json_snapshot(value, field_name="receipt")


class _TranscriptCapture(_VerificationTranscriptObserver):
    def __init__(self) -> None:
        self.validated_artifact: _VerificationArtifactIdentity | None = None
        self.signature_observations: list[_SignatureVerificationObservation] = []
        self.contract_rejection_reason: str | None = None

    def validated_receipt(self, artifact: _VerificationArtifactIdentity) -> None:
        self.validated_artifact = artifact

    def signature_attempt(self, observation: _SignatureVerificationObservation) -> None:
        self.signature_observations.append(observation)

    def contract_rejection(self, reason_id: str) -> None:
        self.contract_rejection_reason = reason_id


def _reason_for_result(result: ShieldV4ReceiptVerificationResult) -> str:
    if result.verified:
        return V4_VERIFY_OK
    dominant = result.dominant_reason_ids[0] if result.dominant_reason_ids else ""
    if dominant == "SIGNATURE_BACKEND_NOT_CONFIGURED":
        return V4_BACKEND_UNAVAILABLE
    if dominant in {"signature verifier failed closed", "signature verifier must return bool"}:
        return V4_BACKEND_FAILURE
    return {
        ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT: V4_CONTRACT_INVALID,
        ShieldV4ReceiptVerificationState.REJECTED_CONTEXT_MISMATCH: V4_CONTEXT_MISMATCH,
        ShieldV4ReceiptVerificationState.REJECTED_REQUEST_MISMATCH: V4_REQUEST_MISMATCH,
        ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT: V4_HASH_MISMATCH,
        ShieldV4ReceiptVerificationState.REJECTED_DOWNGRADE: V4_DOWNGRADE_REJECTED,
        ShieldV4ReceiptVerificationState.REJECTED_AUTHORITY_BYPASS: V4_AUTHORITY_BYPASS,
        ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY: V4_POLICY_INVALID,
        ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY: V4_REGISTRY_INVALID,
        ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW: V4_FRESHNESS_INVALID,
        ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK: V4_REPLAY_REJECTED,
        ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID: V4_SIGNATURE_INVALID,
    }.get(result.state, V4_CONTRACT_INVALID)


def _preflight_record(
    *,
    expected_request_id: str,
    expected_context_hash: str,
    artifact_transport_hash: str,
    minimum_registry_version: int,
    verification_time: str,
    passed: bool,
    reason_id: str,
) -> VerificationPreflightAuditRecord:
    return VerificationPreflightAuditRecord(
        schema_version=AUDIT_SCHEMA_VERSION,
        event_type="verification_preflight",
        verifier_id=AUDIT_VERIFIER_ID,
        verification_timestamp=verification_time,
        verification_passed=passed,
        reason_id=reason_id,
        artifact_type="orchestrator_receipt",
        expected_artifact_schema_version="shield.receipt.v2",
        artifact_transport_hash=artifact_transport_hash,
        expected_request_id_hash=audit_request_id_hash(expected_request_id),
        expected_context_hash=expected_context_hash,
        required_policy_version="policy.v1",
        minimum_registry_version=minimum_registry_version,
    )


def _signature_record(
    observation: _SignatureVerificationObservation,
    *,
    verification_time: str,
) -> SignatureVerificationAuditRecord:
    artifact = observation.artifact
    return SignatureVerificationAuditRecord(
        schema_version=AUDIT_SCHEMA_VERSION,
        event_type="signature_verification",
        verifier_id=AUDIT_VERIFIER_ID,
        verification_timestamp=verification_time,
        verification_passed=observation.verification_passed,
        reason_id=observation.reason_id,
        artifact_type=artifact.artifact_type,
        artifact_schema_version=artifact.artifact_schema_version,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact.artifact_hash,
        request_id_hash=audit_request_id_hash(artifact.request_id),
        context_hash=artifact.context_hash,
        policy_version=artifact.policy_version,
        registry_version=artifact.registry_version,
        key_id_hash=audit_key_id_hash(observation.key_id),
        key_version=observation.key_version,
        algorithm=observation.algorithm,
        standard_profile=observation.standard_profile,
    )


def _terminal_record(
    artifact: _VerificationArtifactIdentity,
    *,
    verification_time: str,
    passed: bool,
    reason_id: str,
) -> ArtifactVerificationAuditRecord:
    return ArtifactVerificationAuditRecord(
        schema_version=AUDIT_SCHEMA_VERSION,
        event_type="artifact_verification",
        verifier_id=AUDIT_VERIFIER_ID,
        verification_timestamp=verification_time,
        verification_passed=passed,
        reason_id=reason_id,
        artifact_type=artifact.artifact_type,
        artifact_schema_version=artifact.artifact_schema_version,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact.artifact_hash,
        request_id_hash=audit_request_id_hash(artifact.request_id),
        context_hash=artifact.context_hash,
        policy_version=artifact.policy_version,
        registry_version=artifact.registry_version,
    )


def _append_required_audit(
    sink: ShieldV4VerificationAuditSink,
    records: tuple[VerificationAuditRecord, ...],
) -> None:
    try:
        encoded_records = tuple(serialize_audit_record(record) for record in records)
        expected_hash = audit_batch_sha256(encoded_records)
        acknowledgement = sink.append_batch(encoded_records)
        valid = (
            type(acknowledgement) is dict
            and all(type(key) is str for key in acknowledgement)
            and set(acknowledgement) == AUDIT_ACK_FIELDS
            and type(acknowledgement["schema_version"]) is str
            and acknowledgement["schema_version"] == AUDIT_ACK_SCHEMA_VERSION
            and type(acknowledgement["batch_sha256"]) is str
            and hmac.compare_digest(
                acknowledgement["batch_sha256"],
                expected_hash,
            )
            and type(acknowledgement["record_count"]) is int
            and acknowledgement["record_count"] == len(encoded_records)
            and acknowledgement["durably_committed"] is True
        )
    except Exception:
        raise ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE") from None
    if not valid:
        raise ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE") from None


def verify_shield_v4_orchestrator_receipt_with_audit(
    receipt: Any,
    *,
    expected_context_hash: str,
    expected_request_id: str,
    trusted_key_registry: Mapping[str, Any],
    verification_time: str,
    audit_sink: ShieldV4VerificationAuditSink,
    artifact_transport_hash: str,
    seen_request_ids: Iterable[str] = (),
    rejected_receipt_hashes: Iterable[str] = (),
    minimum_key_registry_version: int = 1,
    signature_verifier: SignatureVerifier | None = None,
) -> ShieldV4ReceiptVerificationResult:
    """Verify as evidence and return only after an atomic durable audit ACK."""

    verification_time = _validate_timestamp(verification_time)
    expected_context_hash = _validate_sha256(expected_context_hash, field="expected_context_hash")
    artifact_transport_hash = _validate_sha256(artifact_transport_hash, field="artifact_transport_hash")
    try:
        require_bounded_text(expected_request_id, field_name="expected_request_id")
    except ShieldV4WorkBudgetError:
        raise ValueError("expected_request_id must be non-empty string") from None
    try:
        minimum_key_registry_version = require_signed_integer(
            minimum_key_registry_version,
            field_name="minimum_key_registry_version",
        )
    except ShieldV4WorkBudgetError:
        raise ValueError(
            "minimum_key_registry_version must be positive integer",
        ) from None
    if minimum_key_registry_version <= 0:
        raise ValueError("minimum_key_registry_version must be positive integer")
    audit_request_id_hash(expected_request_id)

    capture = _TranscriptCapture()
    try:
        receipt_snapshot = _snapshot_untrusted_receipt(receipt)
        result = _verify_shield_v4_orchestrator_receipt(
            receipt_snapshot,
            expected_context_hash=expected_context_hash,
            expected_request_id=expected_request_id,
            trusted_key_registry=trusted_key_registry,
            verification_time=verification_time,
            seen_request_ids=seen_request_ids,
            rejected_receipt_hashes=rejected_receipt_hashes,
            minimum_key_registry_version=minimum_key_registry_version,
            signature_verifier=signature_verifier,
            transcript_observer=capture,
            receipt_is_bounded_snapshot=True,
        )
    except Exception:
        preflight = _preflight_record(
            expected_request_id=expected_request_id,
            expected_context_hash=expected_context_hash,
            artifact_transport_hash=artifact_transport_hash,
            minimum_registry_version=minimum_key_registry_version,
            verification_time=verification_time,
            passed=False,
            reason_id=V4_CONTRACT_INVALID,
        )
        _append_required_audit(audit_sink, (preflight,))
        raise ShieldV4AuditedVerificationError(V4_CONTRACT_INVALID) from None
    terminal_reason = capture.contract_rejection_reason or _reason_for_result(result)
    records: list[VerificationAuditRecord] = [
        _preflight_record(
            expected_request_id=expected_request_id,
            expected_context_hash=expected_context_hash,
            artifact_transport_hash=artifact_transport_hash,
            minimum_registry_version=minimum_key_registry_version,
            verification_time=verification_time,
            passed=capture.validated_artifact is not None,
            reason_id=V4_VERIFY_OK if capture.validated_artifact is not None else terminal_reason,
        )
    ]
    records.extend(
        _signature_record(observation, verification_time=verification_time)
        for observation in capture.signature_observations
    )
    if capture.validated_artifact is not None:
        records.append(
            _terminal_record(
                capture.validated_artifact,
                verification_time=verification_time,
                passed=result.verified,
                reason_id=terminal_reason,
            )
        )
    _append_required_audit(audit_sink, tuple(records))
    return result
