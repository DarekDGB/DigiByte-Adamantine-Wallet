from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    ALGORITHM_STANDARD_PROFILES,
    ALLOWED_ALGORITHMS,
    COMPONENT_ROLES,
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    RECEIPT_SCHEMA_VERSION,
    REQUIRED_ALGORITHMS,
    SIGNATURE_BUNDLE_FIELDS,
    SIGNATURE_BUNDLE_SCHEMA_VERSION,
    SIGNATURE_ENTRY_FIELDS,
    SIGNATURE_POLICY,
    VERDICT_SCHEMA_VERSION,
    ShieldV4ReceiptAuthorityBypassError,
    ShieldV4ReceiptContractError,
    ShieldV4ReceiptDowngradeError,
    ShieldV4ReceiptHashMismatchError,
    _require_hash as _require_contract_hash,
    _require_signature_encoding,
    validate_shield_v4_receipt_contract,
)

KEY_REGISTRY_SCHEMA_VERSION = "shield.key_registry.v1"
ACTIVE = "active"
REVOKED = "revoked"
ORCHESTRATOR_ROLE = "shield_orchestrator"
SUPPORTED_ROLES = tuple(COMPONENT_ROLES.values()) + (ORCHESTRATOR_ROLE,)
COMPONENT_SIGNATURE_PREFIXES = {
    "adn": "TEST-ONLY-ADN-SIGNATURE",
    "dqsn": "TEST-ONLY-DQSN-SIGNATURE",
    "guardian_wallet": "TEST-ONLY-GUARDIAN-WALLET-SIGNATURE",
    "qwg": "TEST-ONLY-QWG-SIGNATURE",
    "sentinel_ai": "TEST-ONLY-SENTINEL-AI-SIGNATURE",
}


class ShieldV4ReceiptVerificationState(str, Enum):
    """Stable AdamantineOS states for Shield v4 cryptographic evidence verification."""

    VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS = "VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS"
    VERIFIED_DENY_DOMINATES = "VERIFIED_DENY_DOMINATES"
    VERIFIED_HUMAN_REVIEW_REQUIRED = "VERIFIED_HUMAN_REVIEW_REQUIRED"
    REJECTED_INVALID_RECEIPT = "REJECTED_INVALID_RECEIPT"
    REJECTED_CONTEXT_MISMATCH = "REJECTED_CONTEXT_MISMATCH"
    REJECTED_REQUEST_MISMATCH = "REJECTED_REQUEST_MISMATCH"
    REJECTED_TAMPERED_RECEIPT = "REJECTED_TAMPERED_RECEIPT"
    REJECTED_DOWNGRADE = "REJECTED_DOWNGRADE"
    REJECTED_AUTHORITY_BYPASS = "REJECTED_AUTHORITY_BYPASS"
    REJECTED_SIGNATURE_POLICY = "REJECTED_SIGNATURE_POLICY"
    REJECTED_SIGNATURE_INVALID = "REJECTED_SIGNATURE_INVALID"
    REJECTED_KEY_REGISTRY = "REJECTED_KEY_REGISTRY"
    REJECTED_REPLAY_RISK = "REJECTED_REPLAY_RISK"
    REJECTED_FRESHNESS_WINDOW = "REJECTED_FRESHNESS_WINDOW"


V4_VERIFY_OK = "V4_VERIFY_OK"
V4_CONTRACT_INVALID = "V4_CONTRACT_INVALID"
V4_CONTEXT_MISMATCH = "V4_CONTEXT_MISMATCH"
V4_HASH_MISMATCH = "V4_HASH_MISMATCH"
V4_DOWNGRADE_REJECTED = "V4_DOWNGRADE_REJECTED"
V4_AUTHORITY_BYPASS = "V4_AUTHORITY_BYPASS"
V4_POLICY_INVALID = "V4_POLICY_INVALID"
V4_SIGNATURE_INVALID = "V4_SIGNATURE_INVALID"
V4_BACKEND_FAILURE = "V4_BACKEND_FAILURE"


@dataclass(frozen=True)
class ShieldV4ReceiptVerificationResult:
    """Fail-closed Shield v4 verifier result.

    A verified ALLOW is still evidence only. It never becomes AdamantineOS final
    approval, never signs transactions, and never broadcasts.
    """

    state: ShieldV4ReceiptVerificationState
    reason_id: ReasonId
    verified: bool
    accepted_as_evidence: bool
    final_approval: bool
    final_outcome: str | None
    context_hash: str | None
    request_id: str | None
    receipt_hash: str | None
    handoff_allowed: bool
    dominant_reason_ids: tuple[str, ...]
    receipt: Mapping[str, Any] | None = None
    verification_summary: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class TrustedShieldV4Key:
    role: str
    key_id: str
    key_version: int
    algorithm: str
    not_before: str
    not_after: str
    status: str
    public_key: str


@dataclass(frozen=True)
class TrustedShieldV4KeyRegistry:
    schema_version: str
    registry_version: int
    entries: tuple[TrustedShieldV4Key, ...]


@dataclass(frozen=True)
class _VerifierRejection(Exception):
    state: ShieldV4ReceiptVerificationState
    reason_id: ReasonId
    message: str


@dataclass(frozen=True)
class _PreparedSignatureEntry:
    entry: Mapping[str, Any]
    algorithm: str
    standard_profile: str
    key_id: str
    key_version: int


@dataclass(frozen=True)
class _VerificationArtifactIdentity:
    artifact_type: str
    artifact_schema_version: str
    artifact_id: str
    artifact_hash: str
    request_id: str
    context_hash: str
    policy_version: str
    registry_version: int


@dataclass(frozen=True)
class _SignatureVerificationObservation:
    artifact: _VerificationArtifactIdentity
    key_id: str
    key_version: int
    algorithm: str
    standard_profile: str
    verification_passed: bool
    reason_id: str


class _VerificationTranscriptObserver:
    """Private observer used only by the required-audit wrapper."""

    def validated_receipt(self, artifact: _VerificationArtifactIdentity) -> None:  # pragma: no cover
        raise NotImplementedError

    def signature_attempt(self, observation: _SignatureVerificationObservation) -> None:  # pragma: no cover
        raise NotImplementedError

    def contract_rejection(self, reason_id: str) -> None:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class _PreparedSignatureBundle:
    entries: tuple[_PreparedSignatureEntry, ...]


@dataclass(frozen=True)
class _PreparedComponentBundle:
    component_id: str
    component_role: str
    artifact_not_before: str
    artifact_not_after: str
    bundle: _PreparedSignatureBundle
    artifact: _VerificationArtifactIdentity


@dataclass(frozen=True)
class _PreparedReceiptBundles:
    components: tuple[_PreparedComponentBundle, ...]
    orchestrator: _PreparedSignatureBundle
    orchestrator_not_before: str
    orchestrator_not_after: str
    orchestrator_artifact: _VerificationArtifactIdentity


def _string_or_none(payload: Any, key: str) -> str | None:
    if isinstance(payload, Mapping) and isinstance(payload.get(key), str):
        return str(payload[key])
    return None


def _rejected(
    *,
    state: ShieldV4ReceiptVerificationState,
    reason_id: ReasonId,
    payload: Any,
    dominant_reason: str | None = None,
) -> ShieldV4ReceiptVerificationResult:
    return ShieldV4ReceiptVerificationResult(
        state=state,
        reason_id=reason_id,
        verified=False,
        accepted_as_evidence=False,
        final_approval=False,
        final_outcome=None,
        context_hash=_string_or_none(payload, "context_hash"),
        request_id=_string_or_none(payload, "request_id"),
        receipt_hash=_string_or_none(payload, "receipt_hash"),
        handoff_allowed=False,
        dominant_reason_ids=(dominant_reason or state.value,),
        receipt=None,
        verification_summary=None,
    )


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            f"{field} must be non-empty string",
        )
    return value.strip()


def _require_supported_standard_profile_for_signature(*, algorithm: str, standard_profile: Any) -> str:
    clean = _require_non_empty_str(standard_profile, field="standard_profile")
    if clean not in ALGORITHM_STANDARD_PROFILES.get(algorithm, ()):  # defensive even after contract validation.
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "unsupported Shield v4 signature standard_profile",
        )
    return clean


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            f"{field} must be positive integer",
        )
    return value


def _parse_utc(value: Any, *, field: str) -> datetime:
    clean = _require_non_empty_str(value, field=field)
    if not clean.endswith("Z"):
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
            ReasonId.EQC_SHIELD_STALE,
            f"{field} must end in Z",
        )
    try:
        parsed = datetime.fromisoformat(clean[:-1] + "+00:00")
    except ValueError as exc:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
            ReasonId.EQC_SHIELD_STALE,
            f"{field} must be valid RFC3339 UTC",
        ) from exc
    return parsed.astimezone(timezone.utc)


def load_trusted_shield_v4_key_registry(raw: Mapping[str, Any]) -> TrustedShieldV4KeyRegistry:
    if not isinstance(raw, Mapping):
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "trusted key registry must be mapping",
        )
    if set(raw.keys()) != {"schema_version", "registry_version", "entries"}:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "trusted key registry fields must match schema",
        )
    if raw["schema_version"] != KEY_REGISTRY_SCHEMA_VERSION:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "trusted key registry schema mismatch",
        )
    registry_version = _require_positive_int(raw["registry_version"], field="registry_version")
    if not isinstance(raw["entries"], list) or not raw["entries"]:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "trusted key registry entries must be non-empty list",
        )
    entries: list[TrustedShieldV4Key] = []
    seen: set[tuple[str, int, str, str]] = set()
    for entry in raw["entries"]:
        if not isinstance(entry, Mapping):
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key entry must be mapping",
            )
        if set(entry.keys()) != {"role", "key_id", "key_version", "algorithm", "not_before", "not_after", "status", "public_key"}:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key entry fields must match schema",
            )
        role = _require_non_empty_str(entry["role"], field="role")
        if role not in SUPPORTED_ROLES:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key role unsupported",
            )
        key_id = _require_non_empty_str(entry["key_id"], field="key_id")
        key_version = _require_positive_int(entry["key_version"], field="key_version")
        algorithm = _require_non_empty_str(entry["algorithm"], field="algorithm")
        if algorithm not in ALLOWED_ALGORITHMS:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key algorithm unsupported",
            )
        not_before = _require_non_empty_str(entry["not_before"], field="not_before")
        not_after = _require_non_empty_str(entry["not_after"], field="not_after")
        if _parse_utc(not_before, field="key.not_before") >= _parse_utc(not_after, field="key.not_after"):
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key validity window invalid",
            )
        status = _require_non_empty_str(entry["status"], field="status")
        if status not in {ACTIVE, REVOKED}:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "trusted key status unsupported",
            )
        public_key = _require_non_empty_str(entry["public_key"], field="public_key")
        identity = (role, key_version, algorithm, key_id)
        if identity in seen:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "duplicate trusted key entry",
            )
        seen.add(identity)
        entries.append(
            TrustedShieldV4Key(
                role=role,
                key_id=key_id,
                key_version=key_version,
                algorithm=algorithm,
                not_before=not_before,
                not_after=not_after,
                status=status,
                public_key=public_key,
            )
        )
    return TrustedShieldV4KeyRegistry(KEY_REGISTRY_SCHEMA_VERSION, registry_version, tuple(entries))


def _find_key(
    registry: TrustedShieldV4KeyRegistry,
    *,
    role: str,
    key_id: str,
    key_version: int,
    algorithm: str,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
) -> TrustedShieldV4Key:
    verification_dt = _parse_utc(verification_time, field="verification_time")
    artifact_start = _parse_utc(artifact_not_before, field="artifact_not_before")
    artifact_end = _parse_utc(artifact_not_after, field="artifact_not_after")
    if artifact_start >= artifact_end:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
            ReasonId.EQC_SHIELD_STALE,
            "artifact validity window invalid",
        )
    for entry in registry.entries:
        if (entry.role, entry.key_id, entry.key_version, entry.algorithm) == (role, key_id, key_version, algorithm):
            if entry.status != ACTIVE:
                raise _VerifierRejection(
                    ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                    ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                    "trusted key revoked",
                )
            key_start = _parse_utc(entry.not_before, field="key_not_before")
            key_end = _parse_utc(entry.not_after, field="key_not_after")
            if not (key_start <= verification_dt <= key_end):
                raise _VerifierRejection(
                    ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                    ReasonId.EQC_SHIELD_STALE,
                    "trusted key not valid at verification time",
                )
            if not (key_start <= artifact_start <= key_end and key_start <= artifact_end <= key_end):
                raise _VerifierRejection(
                    ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                    ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                    "artifact outside trusted key validity window",
                )
            return entry
    raise _VerifierRejection(
        ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
        ReasonId.EQC_INVALID_SHIELD_BUNDLE,
        "trusted key not found",
    )


def _verify_test_only_signature(entry: Mapping[str, Any], key: TrustedShieldV4Key) -> bool:
    if key.role == ORCHESTRATOR_ROLE:
        expected = hmac.new(
            key.public_key.encode("utf-8"),
            f"{entry['domain_tag']}|{entry['signed_payload_hash']}|{entry['algorithm']}|{entry['standard_profile']}|{entry['key_id']}|{entry['key_version']}".encode("utf-8"),
            "sha256",
        ).hexdigest()
        return hmac.compare_digest(str(entry["signature"]), expected)
    component_id = next((candidate for candidate, role in COMPONENT_ROLES.items() if role == key.role), "")
    prefix = COMPONENT_SIGNATURE_PREFIXES.get(component_id)
    if prefix is None:
        return False
    import hashlib

    expected = hashlib.sha256(
        f"{prefix}\n{key.public_key}\n{entry['algorithm']}\n{entry['standard_profile']}\n{entry['signed_payload_hash']}".encode("utf-8")
    ).hexdigest()
    return hmac.compare_digest(str(entry["signature"]), expected)


SignatureVerifier = Callable[[Mapping[str, Any], TrustedShieldV4Key], bool]


def _signature_policy_rejection(message: str) -> _VerifierRejection:
    return _VerifierRejection(
        ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY,
        ReasonId.EQC_INVALID_SHIELD_BUNDLE,
        message,
    )


def _preflight_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_signed_payload_hash: str,
    expected_domain_tag: str,
) -> _PreparedSignatureBundle:
    if not isinstance(bundle, Mapping):
        raise _signature_policy_rejection("signature bundle must be mapping")
    try:
        bundle_snapshot = dict(bundle)
    except Exception as exc:
        raise _signature_policy_rejection("signature bundle snapshot failed") from exc
    if set(bundle_snapshot) != SIGNATURE_BUNDLE_FIELDS:
        raise _signature_policy_rejection("signature bundle fields must match required schema")
    if bundle_snapshot["schema_version"] != SIGNATURE_BUNDLE_SCHEMA_VERSION:
        raise _signature_policy_rejection("signature bundle schema mismatch")
    if bundle_snapshot["policy_version"] != SIGNATURE_POLICY:
        raise _signature_policy_rejection("signature bundle policy mismatch")
    raw_signatures = bundle_snapshot["signatures"]
    if not isinstance(raw_signatures, list) or not raw_signatures:
        raise _signature_policy_rejection("signature bundle signatures must be non-empty list")
    try:
        signatures = tuple(raw_signatures)
    except Exception as exc:
        raise _signature_policy_rejection("signature list snapshot failed") from exc
    try:
        expected_hash = _require_contract_hash(
            expected_signed_payload_hash,
            field="expected_signed_payload_hash",
        )
    except ShieldV4ReceiptContractError as exc:
        raise _signature_policy_rejection(str(exc)) from exc
    expected_domain = _require_non_empty_str(expected_domain_tag, field="expected_domain_tag")
    seen_algorithms: set[str] = set()
    seen_keys: set[tuple[str, int]] = set()
    prepared_entries: list[_PreparedSignatureEntry] = []
    algorithm_sequence: list[str] = []
    for raw_entry in signatures:
        if not isinstance(raw_entry, Mapping):
            raise _signature_policy_rejection("signature entry must be mapping")
        try:
            entry = dict(raw_entry)
        except Exception as exc:
            raise _signature_policy_rejection("signature entry snapshot failed") from exc
        if set(entry) != SIGNATURE_ENTRY_FIELDS:
            raise _signature_policy_rejection("signature entry fields must match required schema")
        algorithm = _require_non_empty_str(entry["algorithm"], field="algorithm")
        if algorithm not in ALLOWED_ALGORITHMS:
            raise _signature_policy_rejection("unsupported Shield v4 signature algorithm")
        if algorithm in seen_algorithms:
            raise _signature_policy_rejection("duplicate signature algorithm")
        seen_algorithms.add(algorithm)
        algorithm_sequence.append(algorithm)
        standard_profile = _require_supported_standard_profile_for_signature(
            algorithm=algorithm,
            standard_profile=entry["standard_profile"],
        )
        key_id = _require_non_empty_str(entry["key_id"], field="key_id")
        key_version = _require_positive_int(entry["key_version"], field="key_version")
        key_identity = (key_id, key_version)
        if key_identity in seen_keys:
            raise _signature_policy_rejection("duplicate signature key entry")
        seen_keys.add(key_identity)
        try:
            entry_hash = _require_contract_hash(
                entry["signed_payload_hash"],
                field="signed_payload_hash",
            )
            _require_signature_encoding(entry["signature"], field="signature")
        except ShieldV4ReceiptContractError as exc:
            raise _signature_policy_rejection(str(exc)) from exc
        if entry_hash != expected_hash:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "signature hash mismatch",
            )
        if _require_non_empty_str(entry["domain_tag"], field="domain_tag") != expected_domain:
            raise _signature_policy_rejection("signature domain mismatch")
        prepared_entries.append(
            _PreparedSignatureEntry(
                entry=entry,
                algorithm=algorithm,
                standard_profile=standard_profile,
                key_id=key_id,
                key_version=key_version,
            )
        )
    canonical_sequence = [algorithm for algorithm in ALLOWED_ALGORITHMS if algorithm in seen_algorithms]
    if algorithm_sequence != canonical_sequence:
        raise _signature_policy_rejection("signature algorithms must use canonical policy order")
    missing = set(REQUIRED_ALGORITHMS) - seen_algorithms
    if missing:
        raise _signature_policy_rejection("signature policy requirements not satisfied")
    return _PreparedSignatureBundle(tuple(prepared_entries))


def _preflight_receipt_bundles(receipt: Mapping[str, Any]) -> _PreparedReceiptBundles:
    components: list[_PreparedComponentBundle] = []
    for component in receipt["component_verdicts"]:
        component_id = str(component["component_id"])
        components.append(
            _PreparedComponentBundle(
                component_id=component_id,
                component_role=COMPONENT_ROLES[component_id],
                artifact_not_before=str(component["not_before"]),
                artifact_not_after=str(component["not_after"]),
                bundle=_preflight_bundle(
                    component["signature_bundle"],
                    expected_signed_payload_hash=str(component["signed_payload_hash"]),
                    expected_domain_tag=COMPONENT_VERDICT_DOMAIN,
                ),
                artifact=_VerificationArtifactIdentity(
                    artifact_type="component_verdict",
                    artifact_schema_version=VERDICT_SCHEMA_VERSION,
                    artifact_id=component_id,
                    artifact_hash=str(component["signed_payload_hash"]),
                    request_id=str(component["request_id"]),
                    context_hash=str(component["context_hash"]),
                    policy_version=str(component["signature_policy"]),
                    registry_version=int(component["key_registry_version"]),
                ),
            )
        )
    return _PreparedReceiptBundles(
        components=tuple(components),
        orchestrator=_preflight_bundle(
            receipt["signature_bundle"],
            expected_signed_payload_hash=str(receipt["signed_payload_hash"]),
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        ),
        orchestrator_not_before=str(receipt["not_before"]),
        orchestrator_not_after=str(receipt["not_after"]),
        orchestrator_artifact=_VerificationArtifactIdentity(
            artifact_type="orchestrator_receipt",
            artifact_schema_version=RECEIPT_SCHEMA_VERSION,
            artifact_id="shield_orchestrator",
            artifact_hash=str(receipt["signed_payload_hash"]),
            request_id=str(receipt["request_id"]),
            context_hash=str(receipt["context_hash"]),
            policy_version=str(receipt["signature_policy"]),
            registry_version=int(receipt["key_registry_version"]),
        ),
    )


def _verify_prepared_bundle(
    prepared_bundle: _PreparedSignatureBundle,
    *,
    required_role: str,
    registry: TrustedShieldV4KeyRegistry,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
    signature_verifier: SignatureVerifier,
    artifact: _VerificationArtifactIdentity | None = None,
    transcript_observer: _VerificationTranscriptObserver | None = None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for prepared in prepared_bundle.entries:
        key = _find_key(
            registry,
            role=required_role,
            key_id=prepared.key_id,
            key_version=prepared.key_version,
            algorithm=prepared.algorithm,
            verification_time=verification_time,
            artifact_not_before=artifact_not_before,
            artifact_not_after=artifact_not_after,
        )
        try:
            verified = signature_verifier(prepared.entry, key)
        except Exception as exc:
            if transcript_observer is not None and artifact is not None:
                transcript_observer.signature_attempt(
                    _SignatureVerificationObservation(
                        artifact=artifact,
                        key_id=prepared.key_id,
                        key_version=prepared.key_version,
                        algorithm=prepared.algorithm,
                        standard_profile=prepared.standard_profile,
                        verification_passed=False,
                        reason_id=V4_BACKEND_FAILURE,
                    )
                )
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "signature verifier failed closed",
            ) from exc
        if not isinstance(verified, bool):
            if transcript_observer is not None and artifact is not None:
                transcript_observer.signature_attempt(
                    _SignatureVerificationObservation(
                        artifact=artifact,
                        key_id=prepared.key_id,
                        key_version=prepared.key_version,
                        algorithm=prepared.algorithm,
                        standard_profile=prepared.standard_profile,
                        verification_passed=False,
                        reason_id=V4_BACKEND_FAILURE,
                    )
                )
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "signature verifier must return bool",
            )
        if not verified:
            if transcript_observer is not None and artifact is not None:
                transcript_observer.signature_attempt(
                    _SignatureVerificationObservation(
                        artifact=artifact,
                        key_id=prepared.key_id,
                        key_version=prepared.key_version,
                        algorithm=prepared.algorithm,
                        standard_profile=prepared.standard_profile,
                        verification_passed=False,
                        reason_id=V4_SIGNATURE_INVALID,
                    )
                )
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "signature verification failed",
            )
        results.append(
            {
                "algorithm": prepared.algorithm,
                "standard_profile": prepared.standard_profile,
                "key_id": prepared.key_id,
                "key_version": prepared.key_version,
                "verified": True,
            }
        )
        if transcript_observer is not None and artifact is not None:
            transcript_observer.signature_attempt(
                _SignatureVerificationObservation(
                    artifact=artifact,
                    key_id=prepared.key_id,
                    key_version=prepared.key_version,
                    algorithm=prepared.algorithm,
                    standard_profile=prepared.standard_profile,
                    verification_passed=True,
                    reason_id=V4_VERIFY_OK,
                )
            )
    return {
        "required_algorithms": list(REQUIRED_ALGORITHMS),
        "verified_algorithms": [r["algorithm"] for r in results],
        "verified_standard_profiles": [r["standard_profile"] for r in results],
        "results": results,
    }


def _verify_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_signed_payload_hash: str,
    expected_domain_tag: str,
    required_role: str,
    registry: TrustedShieldV4KeyRegistry,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
    signature_verifier: SignatureVerifier,
) -> dict[str, Any]:
    prepared_bundle = _preflight_bundle(
        bundle,
        expected_signed_payload_hash=expected_signed_payload_hash,
        expected_domain_tag=expected_domain_tag,
    )
    return _verify_prepared_bundle(
        prepared_bundle,
        required_role=required_role,
        registry=registry,
        verification_time=verification_time,
        artifact_not_before=artifact_not_before,
        artifact_not_after=artifact_not_after,
        signature_verifier=signature_verifier,
    )


def _enforce_registry_versions(
    receipt: Mapping[str, Any],
    *,
    registry: TrustedShieldV4KeyRegistry,
    minimum_key_registry_version: int,
) -> None:
    if registry.registry_version < minimum_key_registry_version:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "trusted key registry rollback rejected",
        )
    if receipt["key_registry_version"] != registry.registry_version:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "receipt key registry version mismatch",
        )
    for component in receipt["component_verdicts"]:
        if component["key_registry_version"] != registry.registry_version:
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY,
                ReasonId.EQC_INVALID_SHIELD_BUNDLE,
                "component key registry version mismatch",
            )


def _enforce_freshness(receipt: Mapping[str, Any], *, verification_time: str) -> None:
    now = _parse_utc(verification_time, field="verification_time")
    not_before = _parse_utc(receipt["not_before"], field="receipt.not_before")
    not_after = _parse_utc(receipt["not_after"], field="receipt.not_after")
    if not_before >= not_after:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
            ReasonId.EQC_SHIELD_STALE,
            "receipt freshness window invalid",
        )
    if not (not_before <= now <= not_after):
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
            ReasonId.EQC_SHIELD_STALE,
            "receipt outside freshness window",
        )
    for component in receipt["component_verdicts"]:
        component_start = _parse_utc(component["not_before"], field="component.not_before")
        component_end = _parse_utc(component["not_after"], field="component.not_after")
        if component_start >= component_end or not (component_start <= now <= component_end):
            raise _VerifierRejection(
                ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW,
                ReasonId.EQC_SHIELD_STALE,
                "component outside freshness window",
            )


def _verify_component_bundles(
    prepared_receipt: _PreparedReceiptBundles,
    *,
    registry: TrustedShieldV4KeyRegistry,
    verification_time: str,
    signature_verifier: SignatureVerifier,
    transcript_observer: _VerificationTranscriptObserver | None = None,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for component in prepared_receipt.components:
        verification = _verify_prepared_bundle(
            component.bundle,
            required_role=component.component_role,
            registry=registry,
            verification_time=verification_time,
            artifact_not_before=component.artifact_not_before,
            artifact_not_after=component.artifact_not_after,
            signature_verifier=signature_verifier,
            artifact=component.artifact,
            transcript_observer=transcript_observer,
        )
        summaries.append(
            {
                "component_id": component.component_id,
                "component_role": component.component_role,
                **verification,
            }
        )
    return summaries


def _normalise_component_signature_result(item: Mapping[str, Any]) -> dict[str, Any]:
    algorithms = item.get("verified_algorithms")
    profiles = item.get("verified_standard_profiles")
    if (
        not isinstance(algorithms, list)
        or any(not isinstance(algorithm, str) for algorithm in algorithms)
        or not isinstance(profiles, list)
        or len(profiles) != len(algorithms)
        or any(not isinstance(profile, str) for profile in profiles)
    ):
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "component signature result mismatch",
        )
    pairs = sorted((str(algorithm), str(profile)) for algorithm, profile in zip(algorithms, profiles, strict=True))
    return {
        "component_id": str(item.get("component_id")),
        "component_role": str(item.get("component_role")),
        "verified": item.get("verified"),
        "verified_algorithms": [algorithm for algorithm, _ in pairs],
        "verified_standard_profiles": [profile for _, profile in pairs],
        "signature_policy": item.get("signature_policy"),
    }


def _cross_check_component_signature_results(
    receipt: Mapping[str, Any],
    component_summaries: list[dict[str, Any]],
) -> None:
    """Reject Orchestrator self-attested component summaries that drift from re-verification."""

    expected = sorted(
        (
            _normalise_component_signature_result(
                {
                    "component_id": str(summary["component_id"]),
                    "component_role": str(summary["component_role"]),
                    "verified": True,
                    "verified_algorithms": list(summary["verified_algorithms"]),
                    "verified_standard_profiles": list(summary["verified_standard_profiles"]),
                    "signature_policy": "policy.v1",
                }
            )
            for summary in component_summaries
        ),
        key=lambda item: item["component_id"],
    )
    claimed = sorted(
        (_normalise_component_signature_result(item) for item in receipt["component_signature_results"]),
        key=lambda item: item["component_id"],
    )
    if claimed != expected:
        raise _VerifierRejection(
            ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY,
            ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            "component signature result mismatch",
        )


def _state_for_final_outcome(final_outcome: str) -> tuple[ShieldV4ReceiptVerificationState, ReasonId]:
    if final_outcome == "DENY":
        return ShieldV4ReceiptVerificationState.VERIFIED_DENY_DOMINATES, ReasonId.DENY_POLICY
    if final_outcome == "HUMAN_REVIEW_REQUIRED":
        return ShieldV4ReceiptVerificationState.VERIFIED_HUMAN_REVIEW_REQUIRED, ReasonId.DENY_AUTHORITY_INSUFFICIENT
    return ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS, ReasonId.EVIDENCE_OK


def _classify_contract_error(exc: ValueError) -> tuple[ShieldV4ReceiptVerificationState, ReasonId, str]:
    if isinstance(exc, ShieldV4ReceiptDowngradeError):
        return ShieldV4ReceiptVerificationState.REJECTED_DOWNGRADE, ReasonId.EQC_INVALID_SHIELD_BUNDLE, "SHIELD_V4_DOWNGRADE_REJECTED"
    if isinstance(exc, ShieldV4ReceiptHashMismatchError):
        return ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT, ReasonId.EQC_INVALID_SHIELD_BUNDLE, "SHIELD_V4_HASH_MISMATCH"
    if isinstance(exc, ShieldV4ReceiptAuthorityBypassError):
        return ShieldV4ReceiptVerificationState.REJECTED_AUTHORITY_BYPASS, ReasonId.EQC_INVALID_SHIELD_BUNDLE, "SHIELD_V4_AUTHORITY_BYPASS"
    if isinstance(exc, ShieldV4ReceiptContractError) and "context" in str(exc).lower():
        return ShieldV4ReceiptVerificationState.REJECTED_CONTEXT_MISMATCH, ReasonId.EQC_SHIELD_CONTEXT_HASH_MISMATCH, "SHIELD_V4_CONTEXT_MISMATCH"
    return ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT, ReasonId.EQC_INVALID_SHIELD_BUNDLE, "SHIELD_V4_INVALID_RECEIPT"


def _audit_reason_for_contract_error(exc: ValueError) -> str:
    if isinstance(exc, ShieldV4ReceiptDowngradeError):
        return V4_DOWNGRADE_REJECTED
    if isinstance(exc, ShieldV4ReceiptHashMismatchError):
        return V4_HASH_MISMATCH
    if isinstance(exc, ShieldV4ReceiptAuthorityBypassError):
        return V4_AUTHORITY_BYPASS
    message = str(exc).lower()
    if "context" in message:
        return V4_CONTEXT_MISMATCH
    if "policy" in message or "signature bundle" in message:
        return V4_POLICY_INVALID
    return V4_CONTRACT_INVALID


def _verify_shield_v4_orchestrator_receipt(
    receipt: Any,
    *,
    expected_context_hash: str,
    expected_request_id: str,
    trusted_key_registry: Mapping[str, Any],
    verification_time: str,
    seen_request_ids: Iterable[str] = (),
    rejected_receipt_hashes: Iterable[str] = (),
    minimum_key_registry_version: int = 1,
    signature_verifier: SignatureVerifier | None = None,
    transcript_observer: _VerificationTranscriptObserver | None = None,
) -> ShieldV4ReceiptVerificationResult:
    """Verify a Shield v4 Orchestrator receipt as evidence only.

    The verifier is deterministic and fail-closed. Replay state, time, trusted key
    registry, and signature verifier are injected by the caller. No production-facing
    default verifier is provided; callers must explicitly inject a real backend or
    the test-only verifier used by fixture tests.
    """

    try:
        valid = validate_shield_v4_receipt_contract(receipt, expected_context_hash=expected_context_hash)
    except ValueError as exc:
        state, reason_id, dominant = _classify_contract_error(exc)
        if transcript_observer is not None:
            transcript_observer.contract_rejection(_audit_reason_for_contract_error(exc))
        return _rejected(state=state, reason_id=reason_id, payload=receipt, dominant_reason=dominant)

    validated_artifact = _VerificationArtifactIdentity(
        artifact_type="orchestrator_receipt",
        artifact_schema_version=RECEIPT_SCHEMA_VERSION,
        artifact_id="shield_orchestrator",
        artifact_hash=str(valid["signed_payload_hash"]),
        request_id=str(valid["request_id"]),
        context_hash=str(valid["context_hash"]),
        policy_version=str(valid["signature_policy"]),
        registry_version=int(valid["key_registry_version"]),
    )
    if transcript_observer is not None:
        transcript_observer.validated_receipt(validated_artifact)

    if not isinstance(expected_request_id, str) or not expected_request_id.strip():
        return _rejected(
            state=ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT,
            reason_id=ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            payload=valid,
            dominant_reason="EXPECTED_REQUEST_ID_INVALID",
        )
    if valid["request_id"] != expected_request_id:
        return _rejected(
            state=ShieldV4ReceiptVerificationState.REJECTED_REQUEST_MISMATCH,
            reason_id=ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            payload=valid,
            dominant_reason="SHIELD_V4_REQUEST_ID_MISMATCH",
        )
    if signature_verifier is None:
        return _rejected(
            state=ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID,
            reason_id=ReasonId.EQC_INVALID_SHIELD_BUNDLE,
            payload=valid,
            dominant_reason="SIGNATURE_BACKEND_NOT_CONFIGURED",
        )
    receipt_hash = str(valid["receipt_hash"])
    if valid["request_id"] in set(seen_request_ids) or receipt_hash in set(rejected_receipt_hashes):
        return _rejected(
            state=ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK,
            reason_id=ReasonId.EQC_SHIELD_STALE,
            payload=valid,
            dominant_reason="SHIELD_V4_REPLAY_REJECTED",
        )

    try:
        prepared_receipt = _preflight_receipt_bundles(valid)
        registry = load_trusted_shield_v4_key_registry(trusted_key_registry)
        _enforce_registry_versions(valid, registry=registry, minimum_key_registry_version=minimum_key_registry_version)
        _enforce_freshness(valid, verification_time=verification_time)
        component_summaries = _verify_component_bundles(
            prepared_receipt,
            registry=registry,
            verification_time=verification_time,
            signature_verifier=signature_verifier,
            transcript_observer=transcript_observer,
        )
        _cross_check_component_signature_results(valid, component_summaries)
        orchestrator_summary = _verify_prepared_bundle(
            prepared_receipt.orchestrator,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=verification_time,
            artifact_not_before=prepared_receipt.orchestrator_not_before,
            artifact_not_after=prepared_receipt.orchestrator_not_after,
            signature_verifier=signature_verifier,
            artifact=prepared_receipt.orchestrator_artifact,
            transcript_observer=transcript_observer,
        )
    except _VerifierRejection as exc:
        return _rejected(state=exc.state, reason_id=exc.reason_id, payload=valid, dominant_reason=exc.message)

    final_outcome = str(valid["final_outcome"])
    state, reason_id = _state_for_final_outcome(final_outcome)
    verification_summary = {
        "key_registry_version": registry.registry_version,
        "policy_version": "policy.v1",
        "orchestrator": orchestrator_summary,
        "components": component_summaries,
    }
    return ShieldV4ReceiptVerificationResult(
        state=state,
        reason_id=reason_id,
        verified=True,
        accepted_as_evidence=True,
        final_approval=False,
        final_outcome=final_outcome,
        context_hash=str(valid["context_hash"]),
        request_id=str(valid["request_id"]),
        receipt_hash=receipt_hash,
        handoff_allowed=bool(valid["adamantineos_handoff"]["handoff_allowed"]),
        dominant_reason_ids=tuple(str(reason_id) for reason_id in valid["dominant_reason_ids"]),
        receipt=valid,
        verification_summary=verification_summary,
    )


def verify_shield_v4_orchestrator_receipt(
    receipt: Any,
    *,
    expected_context_hash: str,
    expected_request_id: str,
    trusted_key_registry: Mapping[str, Any],
    verification_time: str,
    seen_request_ids: Iterable[str] = (),
    rejected_receipt_hashes: Iterable[str] = (),
    minimum_key_registry_version: int = 1,
    signature_verifier: SignatureVerifier | None = None,
) -> ShieldV4ReceiptVerificationResult:
    """Verify a Shield v4 Orchestrator receipt as evidence only.

    The public API and behavior remain unchanged. The required-audit boundary
    uses a separate wrapper and a private, non-authoritative transcript observer.
    """

    return _verify_shield_v4_orchestrator_receipt(
        receipt,
        expected_context_hash=expected_context_hash,
        expected_request_id=expected_request_id,
        trusted_key_registry=trusted_key_registry,
        verification_time=verification_time,
        seen_request_ids=seen_request_ids,
        rejected_receipt_hashes=rejected_receipt_hashes,
        minimum_key_registry_version=minimum_key_registry_version,
        signature_verifier=signature_verifier,
    )
