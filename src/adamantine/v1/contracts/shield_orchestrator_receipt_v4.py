from __future__ import annotations

import base64
import binascii
import hashlib
import json
import unicodedata
from typing import Any

RECEIPT_SCHEMA_VERSION = "shield.receipt.v2"
VERDICT_SCHEMA_VERSION = "shield.verdict.v2"
SIGNATURE_BUNDLE_SCHEMA_VERSION = "shield.signature_bundle.v1"
CONTRACT_VERSION = 4
CANONICALIZATION_PROFILE = "shield-v4-canon.v1"
SIGNATURE_POLICY = "policy.v1"
SIGNED_PAYLOAD_HASH_PREFIX = "DGB-SHIELD-V4-SIGNED-PAYLOAD"
ORCHESTRATOR_RECEIPT_DOMAIN = "DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1"
COMPONENT_VERDICT_DOMAIN = "DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1"
CLASSICAL_ED25519 = "classical-ed25519"
ML_DSA = "ml-dsa"
FN_DSA = "fn-dsa"
REQUIRED_ALGORITHMS = (CLASSICAL_ED25519, ML_DSA)
OPTIONAL_ALGORITHMS = (FN_DSA,)
ALLOWED_ALGORITHMS = REQUIRED_ALGORITHMS + OPTIONAL_ALGORITHMS
ED25519_RFC8032_PROFILE = "rfc8032-ed25519-v1"
FIPS204_ML_DSA_65_PROFILE = "fips204-ml-dsa-65-v1"
FIPS206_DRAFT_FALCON1024_PROFILE = "fips206-draft-falcon1024-v1"
ALGORITHM_STANDARD_PROFILES = {
    CLASSICAL_ED25519: (ED25519_RFC8032_PROFILE,),
    ML_DSA: (FIPS204_ML_DSA_65_PROFILE,),
    FN_DSA: (FIPS206_DRAFT_FALCON1024_PROFILE,),
}
DEFAULT_STANDARD_PROFILE_BY_ALGORITHM = {
    algorithm: profiles[0] for algorithm, profiles in ALGORITHM_STANDARD_PROFILES.items()
}
REAL_SIGNATURE_ENCODING_PREFIX = "b64u:"
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
SUPPORTED_COMPONENTS = ("adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai")
COMPONENT_ROLES = {
    "adn": "shield_component_adn",
    "dqsn": "shield_component_dqsn",
    "guardian_wallet": "shield_component_guardian_wallet",
    "qwg": "shield_component_qwg",
    "sentinel_ai": "shield_component_sentinel_ai",
}
FINAL_OUTCOMES = ("ALLOW", "DENY", "HUMAN_REVIEW_REQUIRED")
COMPONENT_DECISIONS = ("ALLOW", "ESCALATE", "DENY", "ERROR", "SKIPPED")
DENYING_COMPONENT_DECISIONS = frozenset({"DENY", "ERROR"})
ESCALATING_COMPONENT_DECISIONS = frozenset({"ESCALATE", "SKIPPED"})
FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "allow",
        "approved",
        "authority",
        "auto_approve",
        "broadcast",
        "bypass",
        "can_sign",
        "decision",
        "execute",
        "final_approval",
        "force_allow",
        "human_approved",
        "override",
        "sign",
        "trusted",
    }
)
REQUIRED_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "contract_version",
        "request_id",
        "context_hash",
        "freshness_nonce",
        "not_before",
        "not_after",
        "component_verdicts",
        "component_signature_results",
        "final_outcome",
        "dominant_reason_ids",
        "canonicalization_profile",
        "signature_policy",
        "key_registry_version",
        "adamantineos_handoff",
        "fail_closed",
        "receipt_hash",
        "signed_payload_hash",
        "signature_bundle",
    }
)
OPTIONAL_RECEIPT_FIELDS = frozenset({"verification_summary"})
UNSIGNED_RECEIPT_EXCLUDED_FIELDS = frozenset({"receipt_hash", "signed_payload_hash", "signature_bundle", "verification_summary"})
REQUIRED_SIGNED_COMPONENT_FIELDS = frozenset(
    {
        "component_id",
        "contract_version",
        "schema_version",
        "request_id",
        "context_hash",
        "freshness_nonce",
        "not_before",
        "not_after",
        "decision",
        "reason_ids",
        "evidence_hash",
        "evidence_families",
        "metadata",
        "fail_closed",
        "canonicalization_profile",
        "signature_policy",
        "key_registry_version",
        "signed_payload_hash",
        "signature_bundle",
    }
)
OPTIONAL_COMPONENT_FIELDS = frozenset({"verification_summary"})
SIGNATURE_BUNDLE_FIELDS = frozenset({"schema_version", "policy_version", "signatures"})
SIGNATURE_ENTRY_FIELDS = frozenset(
    {"algorithm", "standard_profile", "key_id", "key_version", "signed_payload_hash", "domain_tag", "signature"}
)
COMPONENT_SIGNATURE_RESULT_FIELDS = frozenset(
    {
        "component_id",
        "component_role",
        "verified",
        "verified_algorithms",
        "verified_standard_profiles",
        "signature_policy",
    }
)


class ShieldV4ReceiptContractError(ValueError):
    """Fail-closed base error for Shield v4 receipt contract validation."""


class ShieldV4ReceiptDowngradeError(ShieldV4ReceiptContractError):
    """A Shield v3 receipt was submitted where Shield v4 is required."""


class ShieldV4ReceiptHashMismatchError(ShieldV4ReceiptContractError):
    """The Shield v4 receipt hash or signed payload hash does not match."""


class ShieldV4ReceiptAuthorityBypassError(ShieldV4ReceiptContractError):
    """The Shield v4 receipt tries to carry final execution authority."""


def _normalise(value: Any, *, path: str) -> Any:
    if value is None:
        raise ShieldV4ReceiptContractError(f"{path} must omit absent fields instead of using null")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ShieldV4ReceiptContractError(f"{path} must not contain floats")
    if isinstance(value, list):
        return [_normalise(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, tuple):
        return [_normalise(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        normalised: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ShieldV4ReceiptContractError(f"{path} object keys must be strings")
            clean_key = unicodedata.normalize("NFC", key)
            if clean_key in normalised:
                raise ShieldV4ReceiptContractError(f"{path} contains duplicate key after Unicode normalization")
            normalised[clean_key] = _normalise(item, path=f"{path}.{clean_key}")
        return normalised
    raise ShieldV4ReceiptContractError(f"{path} contains unsupported type {type(value).__name__}")


def to_canonical_json(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        raise ShieldV4ReceiptContractError("payload must be dict")
    return json.dumps(
        _normalise(payload, path="$"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def signed_payload_hash(*, domain_tag: str, payload: dict[str, Any]) -> str:
    if domain_tag not in {ORCHESTRATOR_RECEIPT_DOMAIN, COMPONENT_VERDICT_DOMAIN}:
        raise ShieldV4ReceiptContractError("unsupported Shield v4 domain tag")
    material = f"{SIGNED_PAYLOAD_HASH_PREFIX}\n{domain_tag}\n".encode("utf-8") + to_canonical_json(payload).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def receipt_hash(unsigned_payload: dict[str, Any]) -> str:
    return hashlib.sha256(to_canonical_json(unsigned_payload).encode("utf-8")).hexdigest()


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ShieldV4ReceiptContractError(f"{field} must be non-empty string")
    return value.strip()


def _require_supported_standard_profile(*, algorithm: str, standard_profile: Any) -> str:
    clean = _require_non_empty_str(standard_profile, field="standard_profile")
    if clean not in ALGORITHM_STANDARD_PROFILES.get(algorithm, ()):  # impossible after algorithm allow-list, defensive anyway.
        raise ShieldV4ReceiptContractError("unsupported Shield v4 signature standard_profile")
    return clean


def default_standard_profile_for_algorithm(algorithm: str) -> str:
    if algorithm not in ALLOWED_ALGORITHMS:
        raise ShieldV4ReceiptContractError("unsupported Shield v4 signature algorithm")
    return DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[algorithm]


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShieldV4ReceiptContractError(f"{field} must be positive integer")
    return value


def _require_hash(value: Any, *, field: str) -> str:
    clean = _require_non_empty_str(value, field=field)
    if len(clean) != 64:
        raise ShieldV4ReceiptContractError(f"{field} must be 64-character sha256 hex")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ShieldV4ReceiptContractError(f"{field} must be sha256 hex") from exc
    if clean != clean.lower():
        raise ShieldV4ReceiptContractError(f"{field} must be lowercase sha256 hex")
    return clean


def _require_signature_encoding(value: Any, *, field: str = "signature") -> str:
    """Accept legacy deterministic test digests or explicit real signature encodings."""

    clean = _require_non_empty_str(value, field=field)
    if clean.startswith(REAL_SIGNATURE_ENCODING_PREFIX):
        body = clean[len(REAL_SIGNATURE_ENCODING_PREFIX) :]
        if not body:
            raise ShieldV4ReceiptContractError(f"{field} b64u payload must be non-empty")
        if "=" in body:
            raise ShieldV4ReceiptContractError(f"{field} b64u payload must be unpadded")
        if set(body) - _BASE64URL_ALPHABET:
            raise ShieldV4ReceiptContractError(f"{field} b64u payload is invalid")
        try:
            decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError) as exc:
            raise ShieldV4ReceiptContractError(f"{field} b64u payload is invalid") from exc
        return clean
    return _require_hash(clean, field=field)


def _require_str_list(value: Any, *, field: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ShieldV4ReceiptContractError(f"{field} must be non-empty list")
    output: list[str] = []
    seen: set[str] = set()
    for item in value:
        clean = _require_non_empty_str(item, field=f"{field} entry")
        if clean in seen:
            raise ShieldV4ReceiptContractError(f"{field} entries must be unique")
        seen.add(clean)
        output.append(clean)
    return output


def _contains_forbidden_authority(value: Any) -> bool:
    if isinstance(value, dict):
        if set(value) & FORBIDDEN_AUTHORITY_KEYS:
            return True
        return any(_contains_forbidden_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_authority(item) for item in value)
    return False


def _expected_final_outcome(component_verdicts: list[dict[str, Any]]) -> str:
    decisions = {verdict["decision"] for verdict in component_verdicts}
    if decisions & DENYING_COMPONENT_DECISIONS:
        return "DENY"
    if decisions & ESCALATING_COMPONENT_DECISIONS:
        return "HUMAN_REVIEW_REQUIRED"
    return "ALLOW"


def _validate_signature_bundle_shape(
    bundle: Any,
    *,
    expected_signed_payload_hash: str,
    expected_domain_tag: str,
) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ShieldV4ReceiptContractError("signature bundle must be dict")
    if set(bundle.keys()) != SIGNATURE_BUNDLE_FIELDS:
        raise ShieldV4ReceiptContractError("signature bundle fields must match required schema")
    if bundle["schema_version"] != SIGNATURE_BUNDLE_SCHEMA_VERSION:
        raise ShieldV4ReceiptContractError("signature bundle schema mismatch")
    if bundle["policy_version"] != SIGNATURE_POLICY:
        raise ShieldV4ReceiptContractError("signature bundle policy mismatch")
    if not isinstance(bundle["signatures"], list) or not bundle["signatures"]:
        raise ShieldV4ReceiptContractError("signature bundle signatures must be non-empty list")
    expected_hash = _require_hash(expected_signed_payload_hash, field="expected_signed_payload_hash")
    seen_algorithms: set[str] = set()
    algorithm_sequence: list[str] = []
    for entry in bundle["signatures"]:
        if not isinstance(entry, dict):
            raise ShieldV4ReceiptContractError("signature entry must be dict")
        if set(entry.keys()) != SIGNATURE_ENTRY_FIELDS:
            raise ShieldV4ReceiptContractError("signature entry fields must match required schema")
        algorithm = _require_non_empty_str(entry["algorithm"], field="algorithm")
        if algorithm not in ALLOWED_ALGORITHMS:
            raise ShieldV4ReceiptContractError("unsupported Shield v4 signature algorithm")
        if algorithm in seen_algorithms:
            raise ShieldV4ReceiptContractError("duplicate signature algorithm")
        seen_algorithms.add(algorithm)
        algorithm_sequence.append(algorithm)
        _require_supported_standard_profile(
            algorithm=algorithm,
            standard_profile=entry["standard_profile"],
        )
        _require_non_empty_str(entry["key_id"], field="key_id")
        _require_positive_int(entry["key_version"], field="key_version")
        if _require_hash(entry["signed_payload_hash"], field="signed_payload_hash") != expected_hash:
            raise ShieldV4ReceiptHashMismatchError("signature signed_payload_hash mismatch")
        if _require_non_empty_str(entry["domain_tag"], field="domain_tag") != expected_domain_tag:
            raise ShieldV4ReceiptContractError("signature domain tag mismatch")
        _require_signature_encoding(entry["signature"], field="signature")
    canonical_sequence = [algorithm for algorithm in ALLOWED_ALGORITHMS if algorithm in seen_algorithms]
    if algorithm_sequence != canonical_sequence:
        raise ShieldV4ReceiptContractError("signature algorithms must use canonical policy order")
    missing = set(REQUIRED_ALGORITHMS) - seen_algorithms
    if missing:
        raise ShieldV4ReceiptContractError("signature policy requirements not satisfied")
    return dict(bundle)


def _validate_component_signature_results(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list) or len(results) != len(SUPPORTED_COMPONENTS):
        raise ShieldV4ReceiptContractError("component_signature_results must contain every required component")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise ShieldV4ReceiptContractError("component signature result must be dict")
        if set(result.keys()) != COMPONENT_SIGNATURE_RESULT_FIELDS:
            raise ShieldV4ReceiptContractError("component signature result fields must match required schema")
        component_id = _require_non_empty_str(result["component_id"], field="component_id")
        if component_id not in COMPONENT_ROLES:
            raise ShieldV4ReceiptContractError("unknown component signature result component_id")
        if component_id in seen:
            raise ShieldV4ReceiptContractError("duplicate component signature result")
        seen.add(component_id)
        if result["component_role"] != COMPONENT_ROLES[component_id]:
            raise ShieldV4ReceiptContractError("component signature result role mismatch")
        if result["verified"] is not True:
            raise ShieldV4ReceiptContractError("component signature result must be verified")
        if result["signature_policy"] != SIGNATURE_POLICY:
            raise ShieldV4ReceiptContractError("component signature result policy mismatch")
        algorithms = _require_str_list(result["verified_algorithms"], field="verified_algorithms")
        profiles = _require_str_list(result["verified_standard_profiles"], field="verified_standard_profiles")
        if any(algorithm not in ALLOWED_ALGORITHMS for algorithm in algorithms):
            raise ShieldV4ReceiptContractError("component signature result contains unsupported algorithm")
        if set(REQUIRED_ALGORITHMS) - set(algorithms):
            raise ShieldV4ReceiptContractError("component signature result missing required algorithm")
        if len(profiles) != len(algorithms):
            raise ShieldV4ReceiptContractError("component signature result profile/algorithm mismatch")
        for algorithm, profile in zip(algorithms, profiles, strict=True):
            if profile not in ALGORITHM_STANDARD_PROFILES[algorithm]:
                raise ShieldV4ReceiptContractError("component signature result contains unsupported standard_profile")
        checked.append(dict(result))
    return checked


def _unsigned_component_payload(component: dict[str, Any]) -> dict[str, Any]:
    return {key: component[key] for key in component if key not in {"signed_payload_hash", "signature_bundle", "verification_summary"}}


def validate_component_verdict_contract(component: Any, *, expected_context_hash: str) -> dict[str, Any]:
    if not isinstance(component, dict):
        raise ShieldV4ReceiptContractError("component verdict must be dict")
    if set(component.keys()) - OPTIONAL_COMPONENT_FIELDS != REQUIRED_SIGNED_COMPONENT_FIELDS:
        raise ShieldV4ReceiptContractError("component verdict fields must match Shield v4 schema")
    component_id = _require_non_empty_str(component["component_id"], field="component_id")
    if component_id not in COMPONENT_ROLES:
        raise ShieldV4ReceiptContractError("unsupported Shield v4 component")
    if component["contract_version"] != CONTRACT_VERSION:
        raise ShieldV4ReceiptContractError("component contract mismatch")
    if component["schema_version"] != VERDICT_SCHEMA_VERSION:
        raise ShieldV4ReceiptContractError("component schema mismatch")
    if component["fail_closed"] is not True:
        raise ShieldV4ReceiptContractError("component fail_closed must be true")
    if component["canonicalization_profile"] != CANONICALIZATION_PROFILE:
        raise ShieldV4ReceiptContractError("component canonicalization profile mismatch")
    if component["signature_policy"] != SIGNATURE_POLICY:
        raise ShieldV4ReceiptContractError("component signature policy mismatch")
    if component["decision"] not in COMPONENT_DECISIONS:
        raise ShieldV4ReceiptContractError("unsupported component decision")
    if _require_hash(component["context_hash"], field="context_hash") != _require_hash(
        expected_context_hash,
        field="expected_context_hash",
    ):
        raise ShieldV4ReceiptContractError("component context_hash mismatch")
    _require_non_empty_str(component["request_id"], field="request_id")
    _require_non_empty_str(component["freshness_nonce"], field="freshness_nonce")
    _require_non_empty_str(component["not_before"], field="not_before")
    _require_non_empty_str(component["not_after"], field="not_after")
    _require_hash(component["evidence_hash"], field="evidence_hash")
    _require_str_list(component["reason_ids"], field="reason_ids")
    _require_str_list(component["evidence_families"], field="evidence_families")
    _require_positive_int(component["key_registry_version"], field="key_registry_version")
    if not isinstance(component["metadata"], dict):
        raise ShieldV4ReceiptContractError("component metadata must be dict")
    if _contains_forbidden_authority(component["metadata"]):
        raise ShieldV4ReceiptAuthorityBypassError("component metadata contains forbidden authority field")
    unsigned_payload = _unsigned_component_payload(component)
    expected_payload_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=unsigned_payload)
    if _require_hash(component["signed_payload_hash"], field="signed_payload_hash") != expected_payload_hash:
        raise ShieldV4ReceiptHashMismatchError("component signed payload hash mismatch")
    _validate_signature_bundle_shape(
        component["signature_bundle"],
        expected_signed_payload_hash=expected_payload_hash,
        expected_domain_tag=COMPONENT_VERDICT_DOMAIN,
    )
    return dict(component)


def _validate_component_set(component_verdicts: Any, *, expected_context_hash: str) -> list[dict[str, Any]]:
    if not isinstance(component_verdicts, list) or len(component_verdicts) != len(SUPPORTED_COMPONENTS):
        raise ShieldV4ReceiptContractError("component_verdicts must contain every required Shield v4 component")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for component in component_verdicts:
        validated = validate_component_verdict_contract(component, expected_context_hash=expected_context_hash)
        component_id = validated["component_id"]
        if component_id in seen:
            raise ShieldV4ReceiptContractError("duplicate component verdict")
        seen.add(component_id)
        checked.append(validated)
    return checked


def unsigned_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in receipt if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS}


def validate_shield_v4_receipt_contract(receipt: Any, *, expected_context_hash: str) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ShieldV4ReceiptContractError("receipt must be dict")
    if receipt.get("schema_version") == "shield.receipt.v1" or receipt.get("contract_version") == 3:
        raise ShieldV4ReceiptDowngradeError("Shield v3 receipt submitted where Shield v4 is required")
    if set(receipt.keys()) - OPTIONAL_RECEIPT_FIELDS != REQUIRED_RECEIPT_FIELDS:
        raise ShieldV4ReceiptContractError("receipt fields must match Shield v4 schema")
    if receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ShieldV4ReceiptContractError("receipt schema mismatch")
    if receipt["contract_version"] != CONTRACT_VERSION:
        raise ShieldV4ReceiptContractError("receipt contract mismatch")
    if receipt["fail_closed"] is not True:
        raise ShieldV4ReceiptContractError("receipt fail_closed must be true")
    if receipt["canonicalization_profile"] != CANONICALIZATION_PROFILE:
        raise ShieldV4ReceiptContractError("receipt canonicalization profile mismatch")
    if receipt["signature_policy"] != SIGNATURE_POLICY:
        raise ShieldV4ReceiptContractError("receipt signature policy mismatch")
    if receipt["final_outcome"] not in FINAL_OUTCOMES:
        raise ShieldV4ReceiptContractError("unsupported final outcome")
    context_hash = _require_hash(receipt["context_hash"], field="context_hash")
    if context_hash != _require_hash(expected_context_hash, field="expected_context_hash"):
        raise ShieldV4ReceiptContractError("receipt context mismatch")
    _require_non_empty_str(receipt["request_id"], field="request_id")
    _require_non_empty_str(receipt["freshness_nonce"], field="freshness_nonce")
    _require_non_empty_str(receipt["not_before"], field="not_before")
    _require_non_empty_str(receipt["not_after"], field="not_after")
    _require_positive_int(receipt["key_registry_version"], field="key_registry_version")
    _require_str_list(receipt["dominant_reason_ids"], field="dominant_reason_ids")
    if not isinstance(receipt["adamantineos_handoff"], dict):
        raise ShieldV4ReceiptContractError("adamantineos_handoff must be dict")
    if _contains_forbidden_authority(receipt["adamantineos_handoff"]):
        raise ShieldV4ReceiptAuthorityBypassError("adamantineos_handoff contains forbidden authority field")
    component_results = _validate_component_signature_results(receipt["component_signature_results"])
    component_verdicts = _validate_component_set(receipt["component_verdicts"], expected_context_hash=context_hash)
    expected_outcome = _expected_final_outcome(component_verdicts)
    if receipt["final_outcome"] != expected_outcome:
        raise ShieldV4ReceiptContractError("receipt final outcome does not match component decisions")
    if receipt["final_outcome"] != "ALLOW" and receipt["adamantineos_handoff"].get("handoff_allowed") is True:
        raise ShieldV4ReceiptAuthorityBypassError("non-ALLOW receipt cannot carry handoff_allowed true")
    unsigned_payload = unsigned_receipt_payload(receipt)
    if receipt_hash(unsigned_payload) != _require_hash(receipt["receipt_hash"], field="receipt_hash"):
        raise ShieldV4ReceiptHashMismatchError("receipt hash mismatch")
    expected_payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned_payload)
    if expected_payload_hash != _require_hash(receipt["signed_payload_hash"], field="signed_payload_hash"):
        raise ShieldV4ReceiptHashMismatchError("receipt signed payload hash mismatch")
    _validate_signature_bundle_shape(
        receipt["signature_bundle"],
        expected_signed_payload_hash=expected_payload_hash,
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
    )
    return dict(receipt)
