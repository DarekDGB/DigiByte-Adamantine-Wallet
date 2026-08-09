from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from typing import Any

import adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier as verifier_module
from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    COMPONENT_ROLES,
    COMPONENT_VERDICT_DOMAIN,
    DEFAULT_STANDARD_PROFILE_BY_ALGORITHM,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    receipt_hash,
    signed_payload_hash,
    unsigned_receipt_payload,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    ACTIVE,
    KEY_REGISTRY_SCHEMA_VERSION,
    ORCHESTRATOR_ROLE,
    ShieldV4ReceiptVerificationState,
    _classify_contract_error,
    _find_key,
    _parse_utc,
    _require_non_empty_str,
    _require_positive_int,
    _state_for_final_outcome,
    TrustedShieldV4Key,
    _VerifierRejection,
    _verify_bundle,
    _verify_test_only_signature,
    load_trusted_shield_v4_key_registry,
    verify_shield_v4_orchestrator_receipt,
)

FIXTURES = Path(__file__).resolve().parents[2] / "src" / "adamantine" / "v1" / "fixtures" / "shield_v4"
CTX = "a" * 64
VERIFICATION_TIME = "2026-06-21T00:02:00Z"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def trusted_registry(*, registry_version: int = 1, status: str = ACTIVE, not_before: str = "2026-01-01T00:00:00Z", not_after: str = "2030-01-01T00:00:00Z") -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    roles = list(COMPONENT_ROLES.values()) + [ORCHESTRATOR_ROLE]
    for role in roles:
        for algorithm in ("classical-ed25519", "ml-dsa", "fn-dsa"):
            entries.append(
                {
                    "role": role,
                    "key_id": f"test-{role}-{algorithm}-v1",
                    "key_version": 1,
                    "algorithm": algorithm,
                    "not_before": not_before,
                    "not_after": not_after,
                    "status": status,
                    "public_key": f"TEST-ONLY-PUBLIC-{role}-{algorithm}-v1",
                }
            )
    return {"schema_version": KEY_REGISTRY_SCHEMA_VERSION, "registry_version": registry_version, "entries": entries}


def component_prefix(component_id: str) -> str:
    return {
        "adn": "TEST-ONLY-ADN-SIGNATURE",
        "dqsn": "TEST-ONLY-DQSN-SIGNATURE",
        "guardian_wallet": "TEST-ONLY-GUARDIAN-WALLET-SIGNATURE",
        "qwg": "TEST-ONLY-QWG-SIGNATURE",
        "sentinel_ai": "TEST-ONLY-SENTINEL-AI-SIGNATURE",
    }[component_id]


def sign_component(component: dict[str, Any]) -> None:
    unsigned = {k: component[k] for k in component if k not in {"signed_payload_hash", "signature_bundle", "verification_summary"}}
    component_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=unsigned)
    component["signed_payload_hash"] = component_hash
    role = COMPONENT_ROLES[component["component_id"]]
    signatures = []
    for algorithm in ("classical-ed25519", "ml-dsa"):
        standard_profile = DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[algorithm]
        key_id = f"test-{role}-{algorithm}-v1"
        public_key = f"TEST-ONLY-PUBLIC-{role}-{algorithm}-v1"
        signature = hashlib.sha256(
            f"{component_prefix(component['component_id'])}\n{public_key}\n{algorithm}\n{standard_profile}\n{component_hash}".encode("utf-8")
        ).hexdigest()
        signatures.append(
            {
                "algorithm": algorithm,
                "standard_profile": standard_profile,
                "key_id": key_id,
                "key_version": 1,
                "signed_payload_hash": component_hash,
                "domain_tag": COMPONENT_VERDICT_DOMAIN,
                "signature": signature,
            }
        )
    component["signature_bundle"] = {"schema_version": "shield.signature_bundle.v1", "policy_version": "policy.v1", "signatures": signatures}


def sign_receipt(receipt: dict[str, Any]) -> None:
    unsigned = unsigned_receipt_payload(receipt)
    receipt["receipt_hash"] = receipt_hash(unsigned)
    payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned)
    receipt["signed_payload_hash"] = payload_hash
    signatures = []
    for algorithm in ("classical-ed25519", "ml-dsa"):
        standard_profile = DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[algorithm]
        key_id = f"test-shield_orchestrator-{algorithm}-v1"
        public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
        signatures.append(
            {
                "algorithm": algorithm,
                "standard_profile": standard_profile,
                "key_id": key_id,
                "key_version": 1,
                "signed_payload_hash": payload_hash,
                "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
                "signature": hmac.new(
                    public_key.encode("utf-8"),
                    f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{payload_hash}|{algorithm}|{standard_profile}|{key_id}|1".encode("utf-8"),
                    "sha256",
                ).hexdigest(),
            }
        )
    receipt["signature_bundle"] = {"schema_version": "shield.signature_bundle.v1", "policy_version": "policy.v1", "signatures": signatures}


def resign_all(receipt: dict[str, Any]) -> dict[str, Any]:
    for component in receipt["component_verdicts"]:
        sign_component(component)
    sign_receipt(receipt)
    return receipt


def verify(receipt: Any, **overrides: Any):
    default_request_id = receipt.get("request_id", "req-v4-final") if isinstance(receipt, dict) else "req-v4-final"
    params = {
        "expected_context_hash": CTX,
        "expected_request_id": default_request_id,
        "trusted_key_registry": trusted_registry(),
        "verification_time": VERIFICATION_TIME,
        "signature_verifier": _verify_test_only_signature,
    }
    params.update(overrides)
    return verify_shield_v4_orchestrator_receipt(receipt, **params)


def test_shield_v4_verifier_accepts_allow_and_never_grants_final_approval() -> None:
    result = verify(load_fixture("valid_allow_signed_receipt.json"))

    assert result.state == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert result.reason_id == ReasonId.EVIDENCE_OK
    assert result.verified is True
    assert result.accepted_as_evidence is True
    assert result.final_approval is False
    assert result.final_outcome == "ALLOW"
    assert result.handoff_allowed is True
    assert result.verification_summary is not None
    assert result.verification_summary["orchestrator"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert len(result.verification_summary["components"]) == 5




def test_v48g_r4_shield_v4_verifier_requires_explicit_signature_backend() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    result = verify_shield_v4_orchestrator_receipt(
        valid,
        expected_context_hash=CTX,
        expected_request_id="req-v4-final",
        trusted_key_registry=trusted_registry(),
        verification_time=VERIFICATION_TIME,
    )

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("SIGNATURE_BACKEND_NOT_CONFIGURED",)
    assert result.final_approval is False


def test_v48g_r4_shield_v4_verifier_cross_checks_component_signature_results() -> None:
    receipt = load_fixture("valid_allow_signed_receipt.json")
    receipt["component_signature_results"][0]["verified_algorithms"] = [
        "classical-ed25519",
        "ml-dsa",
        "fn-dsa",
    ]
    receipt["component_signature_results"][0]["verified_standard_profiles"] = [
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["classical-ed25519"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["ml-dsa"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["fn-dsa"],
    ]
    sign_receipt(receipt)

    result = verify(receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("component signature result mismatch",)
    assert result.final_approval is False


def test_shield_v4_verifier_accepts_deny_and_human_review_states() -> None:
    deny = verify(load_fixture("deny_signed_receipt.json"), expected_request_id="req-v4-deny")
    assert deny.state == ShieldV4ReceiptVerificationState.VERIFIED_DENY_DOMINATES
    assert deny.reason_id == ReasonId.DENY_POLICY
    assert deny.handoff_allowed is False

    human = copy.deepcopy(load_fixture("valid_allow_signed_receipt.json"))
    human["component_verdicts"][0]["decision"] = "ESCALATE"
    human["component_verdicts"][0]["reason_ids"] = ["HUMAN_REVIEW_REQUIRED"]
    human["component_signature_results"][0]["verified_algorithms"] = ["classical-ed25519", "ml-dsa"]
    human["final_outcome"] = "HUMAN_REVIEW_REQUIRED"
    human["dominant_reason_ids"] = ["HUMAN_REVIEW_REQUIRED"]
    human["adamantineos_handoff"]["handoff_allowed"] = False
    resign_all(human)

    human_result = verify(human)
    assert human_result.state == ShieldV4ReceiptVerificationState.VERIFIED_HUMAN_REVIEW_REQUIRED
    assert human_result.reason_id == ReasonId.DENY_AUTHORITY_INSUFFICIENT
    assert _state_for_final_outcome("ALLOW")[0] == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS


def test_shield_v4_verifier_rejects_contract_boundary_failures() -> None:
    assert verify(load_fixture("v3_downgrade_rejected.json"), expected_request_id="req-v3-downgrade").state == ShieldV4ReceiptVerificationState.REJECTED_DOWNGRADE
    assert verify(load_fixture("tampered_signature_deny.json")).state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    bad_context = verify(load_fixture("valid_allow_signed_receipt.json"), expected_context_hash="b" * 64)
    assert bad_context.state == ShieldV4ReceiptVerificationState.REJECTED_CONTEXT_MISMATCH

    tampered_hash = copy.deepcopy(load_fixture("valid_allow_signed_receipt.json"))
    tampered_hash["receipt_hash"] = "0" * 64
    assert verify(tampered_hash).state == ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT

    authority = copy.deepcopy(load_fixture("valid_allow_signed_receipt.json"))
    authority["adamantineos_handoff"]["final_approval"] = True
    assert verify(authority).state == ShieldV4ReceiptVerificationState.REJECTED_AUTHORITY_BYPASS


def test_shield_v4_verifier_rejects_request_and_replay_failures() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    assert verify(valid, expected_request_id="").dominant_reason_ids == ("EXPECTED_REQUEST_ID_INVALID",)
    assert verify(valid, expected_request_id="wrong").state == ShieldV4ReceiptVerificationState.REJECTED_REQUEST_MISMATCH
    assert verify(valid, seen_request_ids=["req-v4-final"]).state == ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK
    assert verify(valid, rejected_receipt_hashes=[valid["receipt_hash"]]).state == ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK


def test_shield_v4_verifier_rejects_freshness_window_failures() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    assert verify(valid, verification_time="2026-06-21T00:10:00Z").state == ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW
    assert verify(valid, verification_time="not-a-time").state == ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW

    bad_window = copy.deepcopy(valid)
    bad_window["not_before"] = "2026-06-21T00:05:00Z"
    bad_window["not_after"] = "2026-06-21T00:00:00Z"
    resign_all(bad_window)
    assert verify(bad_window).state == ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW

    bad_component_window = copy.deepcopy(valid)
    bad_component_window["component_verdicts"][0]["not_after"] = "2026-06-20T00:00:00Z"
    sign_component(bad_component_window["component_verdicts"][0])
    sign_receipt(bad_component_window)
    assert verify(bad_component_window).state == ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW


def test_shield_v4_verifier_rejects_key_registry_failures() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    malformed_registry: dict[str, Any] = {"bad": True}
    assert verify(valid, trusted_key_registry=malformed_registry).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert verify(valid, trusted_key_registry=trusted_registry(registry_version=0)).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert verify(valid, minimum_key_registry_version=2).dominant_reason_ids == ("trusted key registry rollback rejected",)
    assert verify(valid, trusted_key_registry=trusted_registry(status="revoked")).dominant_reason_ids == ("trusted key revoked",)
    assert verify(valid, trusted_key_registry=trusted_registry(not_before="2027-01-01T00:00:00Z", not_after="2030-01-01T00:00:00Z")).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    mismatch_registry = trusted_registry(registry_version=2)
    assert verify(valid, trusted_key_registry=mismatch_registry).dominant_reason_ids == ("receipt key registry version mismatch",)

    component_mismatch = copy.deepcopy(valid)
    component_mismatch["component_verdicts"][0]["key_registry_version"] = 2
    sign_component(component_mismatch["component_verdicts"][0])
    sign_receipt(component_mismatch)
    assert verify(component_mismatch).dominant_reason_ids == ("component key registry version mismatch",)

    missing_key_registry = trusted_registry()
    missing_key_registry["entries"] = missing_key_registry["entries"][1:]
    assert verify(valid, trusted_key_registry=missing_key_registry).dominant_reason_ids == ("trusted key not found",)


def test_shield_v4_verifier_rejects_signature_failures() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    bad_signature = copy.deepcopy(valid)
    bad_signature["signature_bundle"]["signatures"][0]["signature"] = "0" * 64
    assert verify(bad_signature).state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID

    weak_policy = copy.deepcopy(valid)
    weak_policy["signature_bundle"]["signatures"] = weak_policy["signature_bundle"]["signatures"][:1]
    assert verify(weak_policy).state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    duplicate_algorithm = copy.deepcopy(valid)
    duplicate_algorithm["signature_bundle"]["signatures"][1]["algorithm"] = "classical-ed25519"
    duplicate_algorithm["signature_bundle"]["signatures"][1]["key_id"] = "test-shield_orchestrator-classical-ed25519-v1"
    assert verify(duplicate_algorithm).state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    duplicate_key = copy.deepcopy(valid)
    duplicate_key["signature_bundle"]["signatures"][1]["key_id"] = duplicate_key["signature_bundle"]["signatures"][0]["key_id"]
    duplicate_key["signature_bundle"]["signatures"][1]["key_version"] = duplicate_key["signature_bundle"]["signatures"][0]["key_version"]
    assert verify(duplicate_key).state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY

    wrong_domain = copy.deepcopy(valid)
    wrong_domain["signature_bundle"]["signatures"][0]["domain_tag"] = COMPONENT_VERDICT_DOMAIN
    assert verify(wrong_domain).state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    wrong_hash = copy.deepcopy(valid)
    wrong_hash["signature_bundle"]["signatures"][0]["signed_payload_hash"] = "0" * 64
    assert verify(wrong_hash).state == ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT

    bad_component_signature = copy.deepcopy(valid)
    bad_component_signature["component_verdicts"][0]["signature_bundle"]["signatures"][0]["signature"] = "0" * 64
    sign_receipt(bad_component_signature)
    assert verify(bad_component_signature).state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID


@pytest.mark.parametrize("bundle_target", ("orchestrator", "last_component"))
def test_v49j_receipt_wide_preflight_rejects_duplicate_key_before_trust_or_crypto(
    bundle_target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = copy.deepcopy(load_fixture("valid_allow_signed_receipt.json"))
    if bundle_target == "orchestrator":
        signatures = receipt["signature_bundle"]["signatures"]
    else:
        signatures = receipt["component_verdicts"][-1]["signature_bundle"]["signatures"]
    signatures[1]["key_id"] = signatures[0]["key_id"]
    signatures[1]["key_version"] = signatures[0]["key_version"]
    if bundle_target == "last_component":
        sign_receipt(receipt)

    calls = {"trust": 0, "crypto": 0}

    def forbidden_key_lookup(*_args, **_kwargs):
        calls["trust"] += 1
        raise AssertionError("trust lookup must not run before whole-receipt preflight")

    def forbidden_crypto(_entry, _key):
        calls["crypto"] += 1
        raise AssertionError("crypto must not run before whole-receipt preflight")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key_lookup)
    result = verify(receipt, signature_verifier=forbidden_crypto)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY
    assert result.dominant_reason_ids == ("duplicate signature key entry",)
    assert result.final_approval is False
    assert calls == {"trust": 0, "crypto": 0}


def test_shield_v4_verifier_internal_registry_guards_are_fail_closed() -> None:
    base = trusted_registry()
    assert load_trusted_shield_v4_key_registry(base).registry_version == 1

    cases = [
        123,
        {"schema_version": "wrong", "registry_version": 1, "entries": base["entries"]},
        {"schema_version": KEY_REGISTRY_SCHEMA_VERSION, "registry_version": 1, "entries": []},
        {"schema_version": KEY_REGISTRY_SCHEMA_VERSION, "registry_version": 1, "entries": ["bad"]},
        {"schema_version": KEY_REGISTRY_SCHEMA_VERSION, "registry_version": 1, "entries": [{"role": "bad"}]},
    ]
    for registry in cases:
        try:
            load_trusted_shield_v4_key_registry(registry)  # type: ignore[arg-type]
        except Exception as exc:
            assert "REJECTED_KEY_REGISTRY" in str(exc) or exc.__class__.__name__ == "_VerifierRejection"

    bad_entry = copy.deepcopy(base)
    bad_entry["entries"][0]["role"] = "unknown"
    assert verify(load_fixture("valid_allow_signed_receipt.json"), trusted_key_registry=bad_entry).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    bad_entry = copy.deepcopy(base)
    bad_entry["entries"][0]["algorithm"] = "unknown"
    assert verify(load_fixture("valid_allow_signed_receipt.json"), trusted_key_registry=bad_entry).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    bad_entry = copy.deepcopy(base)
    bad_entry["entries"][0]["status"] = "paused"
    assert verify(load_fixture("valid_allow_signed_receipt.json"), trusted_key_registry=bad_entry).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    bad_entry = copy.deepcopy(base)
    bad_entry["entries"].append(copy.deepcopy(bad_entry["entries"][0]))
    assert verify(load_fixture("valid_allow_signed_receipt.json"), trusted_key_registry=bad_entry).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY


def test_shield_v4_verifier_small_helper_edges() -> None:
    assert _parse_utc("2026-01-01T00:00:00Z", field="t").year == 2026
    assert _require_non_empty_str(" ok ", field="x") == "ok"
    assert _require_positive_int(1, field="n") == 1
    assert _classify_contract_error(ValueError("plain"))[0] == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    registry = load_trusted_shield_v4_key_registry(trusted_registry())
    key = _find_key(
        registry,
        role="shield_component_qwg",
        key_id="test-shield_component_qwg-classical-ed25519-v1",
        key_version=1,
        algorithm="classical-ed25519",
        verification_time=VERIFICATION_TIME,
        artifact_not_before="2026-06-21T00:00:00Z",
        artifact_not_after="2026-06-21T00:05:00Z",
    )
    assert key.role == "shield_component_qwg"
    assert _verify_test_only_signature({"signature": "bad", "domain_tag": "x", "signed_payload_hash": "y", "algorithm": "z", "standard_profile": "bad-profile", "key_id": "k", "key_version": 1}, key) is False


def test_shield_v4_verifier_private_policy_guards_are_fail_closed() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")
    registry = load_trusted_shield_v4_key_registry(trusted_registry())
    bundle = copy.deepcopy(valid["signature_bundle"])

    duplicate_algorithm = copy.deepcopy(bundle)
    duplicate_algorithm["signatures"][1]["algorithm"] = "classical-ed25519"
    with pytest.raises(_VerifierRejection, match="duplicate signature algorithm"):
        _verify_bundle(
            duplicate_algorithm,
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=_verify_test_only_signature,
        )

    duplicate_key = copy.deepcopy(bundle)
    duplicate_key["signatures"][1]["key_id"] = duplicate_key["signatures"][0]["key_id"]
    duplicate_key["signatures"][1]["key_version"] = duplicate_key["signatures"][0]["key_version"]
    with pytest.raises(_VerifierRejection, match="duplicate signature key entry"):
        _verify_bundle(
            duplicate_key,
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=_verify_test_only_signature,
        )

    wrong_hash = copy.deepcopy(bundle)
    wrong_hash["signatures"][0]["signed_payload_hash"] = "0" * 64
    with pytest.raises(_VerifierRejection, match="signature hash mismatch"):
        _verify_bundle(
            wrong_hash,
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=_verify_test_only_signature,
        )

    wrong_domain = copy.deepcopy(bundle)
    wrong_domain["signatures"][0]["domain_tag"] = COMPONENT_VERDICT_DOMAIN
    with pytest.raises(_VerifierRejection, match="signature domain mismatch"):
        _verify_bundle(
            wrong_domain,
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=_verify_test_only_signature,
        )

    missing_required = copy.deepcopy(bundle)
    missing_required["signatures"] = missing_required["signatures"][:1]
    with pytest.raises(_VerifierRejection, match="signature policy requirements"):
        _verify_bundle(
            missing_required,
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=_verify_test_only_signature,
        )


def test_shield_v4_verifier_remaining_fail_closed_edges() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    assert verify(["not", "a", "receipt"]).state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    with pytest.raises(_VerifierRejection, match="must be non-empty string"):
        _require_non_empty_str("", field="empty")
    with pytest.raises(_VerifierRejection, match="must be positive integer"):
        _require_positive_int(True, field="bad")
    with pytest.raises(_VerifierRejection, match="valid RFC3339"):
        _parse_utc("2026-99-99T00:00:00Z", field="bad_time")

    bad_key_window = trusted_registry()
    bad_key_window["entries"][0]["not_before"] = "2026-06-21T00:05:00Z"
    bad_key_window["entries"][0]["not_after"] = "2026-06-21T00:00:00Z"
    assert verify(valid, trusted_key_registry=bad_key_window).state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    registry = load_trusted_shield_v4_key_registry(trusted_registry())
    with pytest.raises(_VerifierRejection, match="artifact validity window invalid"):
        _find_key(
            registry,
            role=ORCHESTRATOR_ROLE,
            key_id="test-shield_orchestrator-classical-ed25519-v1",
            key_version=1,
            algorithm="classical-ed25519",
            verification_time=VERIFICATION_TIME,
            artifact_not_before="2026-06-21T00:05:00Z",
            artifact_not_after="2026-06-21T00:00:00Z",
        )

    narrow_registry = trusted_registry(not_before="2026-06-21T00:00:00Z", not_after="2026-06-21T00:03:00Z")
    assert verify(valid, trusted_key_registry=narrow_registry).dominant_reason_ids == ("artifact outside trusted key validity window",)

    unknown_role_key = TrustedShieldV4Key(
        role="unknown",
        key_id="k",
        key_version=1,
        algorithm="classical-ed25519",
        not_before="2026-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
        status=ACTIVE,
        public_key="pk",
    )
    assert _verify_test_only_signature({"signature": "bad", "domain_tag": "x", "signed_payload_hash": "y", "algorithm": "z", "standard_profile": "bad-profile", "key_id": "k", "key_version": 1}, unknown_role_key) is False


def test_v48g_shield_v4_verifier_wraps_signature_verifier_exceptions_fail_closed() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    class NativeVerifierError(RuntimeError):
        pass

    def raising_signature_verifier(_entry, _key):
        raise NativeVerifierError("native verifier crash")

    result = verify(valid, signature_verifier=raising_signature_verifier)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("signature verifier failed closed",)

    registry = load_trusted_shield_v4_key_registry(trusted_registry())
    with pytest.raises(_VerifierRejection, match="signature verifier failed closed") as excinfo:
        _verify_bundle(
            valid["signature_bundle"],
            expected_signed_payload_hash=valid["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=VERIFICATION_TIME,
            artifact_not_before=valid["not_before"],
            artifact_not_after=valid["not_after"],
            signature_verifier=raising_signature_verifier,
        )
    assert isinstance(excinfo.value.__cause__, NativeVerifierError)


def test_v48g_shield_v4_verifier_rejects_truthy_non_bool_signature_verifier_result() -> None:
    valid = load_fixture("valid_allow_signed_receipt.json")

    def truthy_non_bool_signature_verifier(_entry, _key):
        return 1

    result = verify(valid, signature_verifier=truthy_non_bool_signature_verifier)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("signature verifier must return bool",)
