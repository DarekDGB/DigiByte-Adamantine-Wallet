from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

import adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier as verifier_module

from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    COMPONENT_ROLES,
    COMPONENT_VERDICT_DOMAIN,
    DEFAULT_STANDARD_PROFILE_BY_ALGORITHM,
    FN_DSA,
    ShieldV4ReceiptContractError,
    default_standard_profile_for_algorithm,
    ML_DSA,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    REQUIRED_ALGORITHMS,
    receipt_hash,
    signed_payload_hash,
    unsigned_receipt_payload,
    _validate_component_signature_results,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    KEY_REGISTRY_SCHEMA_VERSION,
    ORCHESTRATOR_ROLE,
    ShieldV4ReceiptVerificationState,
    _VerifierRejection,
    _normalise_component_signature_result,
    _verify_bundle,
    _verify_test_only_signature,
    load_trusted_shield_v4_key_registry,
    verify_shield_v4_orchestrator_receipt,
)

FIXTURES = Path(__file__).resolve().parents[2] / "src" / "adamantine" / "v1" / "fixtures" / "shield_v4"
FN_DSA_PROFILE = "fips206-draft-falcon1024-v1"
NONCANONICAL_SIGNATURE_SEQUENCES = (
    (ML_DSA, "classical-ed25519"),
    (FN_DSA, "classical-ed25519", ML_DSA),
    (FN_DSA, ML_DSA, "classical-ed25519"),
    ("classical-ed25519", FN_DSA, ML_DSA),
    (ML_DSA, "classical-ed25519", FN_DSA),
    (ML_DSA, FN_DSA, "classical-ed25519"),
)
MISSING_REQUIRED_SIGNATURE_SEQUENCES = (
    ("classical-ed25519",),
    (ML_DSA,),
    (FN_DSA,),
    ("classical-ed25519", FN_DSA),
    (ML_DSA, FN_DSA),
)


class _FlipAfterFirstSnapshotMapping(Mapping[str, Any]):
    def __init__(self, valid: dict[str, Any], flipped: dict[str, Any]) -> None:
        self._valid = valid
        self._flipped = flipped
        self._reads = 0

    def __getitem__(self, key: str) -> Any:
        source = self._valid if self._reads < len(self._valid) else self._flipped
        self._reads += 1
        return source[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._valid)

    def __len__(self) -> int:
        return len(self._valid)


class _ExplodingMapping(Mapping[str, Any]):
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        raise RuntimeError(f"snapshot blocked for {key}")

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


class _ExplodingList(list[Any]):
    def __iter__(self) -> Iterator[Any]:
        raise RuntimeError("signature list snapshot blocked")


def _load_flow_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _verify_flow(flow: dict[str, Any], receipt: dict[str, Any] | None = None):
    candidate = receipt or flow["receipt"]
    return verify_shield_v4_orchestrator_receipt(
        candidate,
        expected_context_hash=flow["expected_context_hash"],
        expected_request_id=flow["expected_request_id"],
        trusted_key_registry=flow["trusted_key_registry"],
        verification_time=flow["verification_time"],
        signature_verifier=_verify_test_only_signature,
    )


def _resign_orchestrator_receipt(receipt: dict[str, Any]) -> None:
    unsigned = unsigned_receipt_payload(receipt)
    receipt["receipt_hash"] = receipt_hash(unsigned)
    payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned)
    receipt["signed_payload_hash"] = payload_hash
    signatures: list[dict[str, Any]] = []
    for existing in receipt["signature_bundle"]["signatures"]:
        algorithm = existing["algorithm"]
        standard_profile = DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[algorithm]
        key_id = f"test-shield_orchestrator-{algorithm}-v1"
        key_version = 1
        public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
        signatures.append(
            {
                "algorithm": algorithm,
                "standard_profile": standard_profile,
                "key_id": key_id,
                "key_version": key_version,
                "signed_payload_hash": payload_hash,
                "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
                "signature": hmac.new(
                    public_key.encode("utf-8"),
                    f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{payload_hash}|{algorithm}|{standard_profile}|{key_id}|{key_version}".encode(
                        "utf-8"
                    ),
                    "sha256",
                ).hexdigest(),
            }
        )
    receipt["signature_bundle"] = {
        "schema_version": "shield.signature_bundle.v1",
        "policy_version": "policy.v1",
        "signatures": signatures,
    }


def _component_fn_dsa_signature(receipt: dict[str, Any], component_index: int = 0) -> dict[str, Any]:
    for entry in receipt["component_verdicts"][component_index]["signature_bundle"]["signatures"]:
        if entry["algorithm"] == FN_DSA:
            return entry
    raise AssertionError("fixture did not contain component FN-DSA signature")


def _orchestrator_signature(receipt: dict[str, Any], algorithm: str) -> dict[str, Any]:
    for entry in receipt["signature_bundle"]["signatures"]:
        if entry["algorithm"] == algorithm:
            return entry
    raise AssertionError(f"fixture did not contain {algorithm} signature")


def _ordered_signatures(
    signatures: list[dict[str, Any]],
    algorithm_sequence: tuple[str, ...],
) -> list[dict[str, Any]]:
    by_algorithm = {entry["algorithm"]: entry for entry in signatures}
    return [by_algorithm[algorithm] for algorithm in algorithm_sequence]


def _verify_direct_orchestrator_bundle(
    *,
    flow: dict[str, Any],
    bundle: Any,
    signature_verifier,
    expected_signed_payload_hash: str | None = None,
):
    receipt = flow["receipt"]
    return _verify_bundle(
        bundle,
        expected_signed_payload_hash=(
            expected_signed_payload_hash or receipt["signed_payload_hash"]
        ),
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        required_role=ORCHESTRATOR_ROLE,
        registry=load_trusted_shield_v4_key_registry(flow["trusted_key_registry"]),
        verification_time=flow["verification_time"],
        artifact_not_before=receipt["not_before"],
        artifact_not_after=receipt["not_after"],
        signature_verifier=signature_verifier,
    )


def test_v48h_adamantineos_accepts_fn_dsa_absent_and_valid_fn_dsa_present() -> None:
    no_fn_flow = _load_flow_fixture("full_multi_repo_v4_allow_flow.json")
    no_fn_result = _verify_flow(no_fn_flow)
    assert no_fn_result.state == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert no_fn_result.reason_id == ReasonId.EVIDENCE_OK
    assert no_fn_result.final_approval is False
    assert no_fn_result.verification_summary is not None
    assert no_fn_result.verification_summary["orchestrator"]["verified_algorithms"] == list(REQUIRED_ALGORITHMS)

    fn_flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    fn_result = _verify_flow(fn_flow)
    assert fn_result.state == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert fn_result.reason_id == ReasonId.EVIDENCE_OK
    assert fn_result.verified is True
    assert fn_result.accepted_as_evidence is True
    assert fn_result.final_approval is False
    assert fn_result.verification_summary is not None
    assert fn_result.verification_summary["orchestrator"]["verified_algorithms"] == ["classical-ed25519", ML_DSA, FN_DSA]
    assert FN_DSA_PROFILE in fn_result.verification_summary["orchestrator"]["verified_standard_profiles"]
    assert all(FN_DSA in component["verified_algorithms"] for component in fn_result.verification_summary["components"])


@pytest.mark.parametrize("algorithm", ["classical-ed25519", ML_DSA])
def test_v48h_fn_dsa_cannot_rescue_required_orchestrator_signature_failure(algorithm: str) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _orchestrator_signature(receipt, algorithm)["signature"] = "0" * 64

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


@pytest.mark.parametrize("algorithm", ["classical-ed25519", ML_DSA])
def test_v48h_fn_dsa_cannot_rescue_required_component_signature_failure(algorithm: str) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    for entry in receipt["component_verdicts"][0]["signature_bundle"]["signatures"]:
        if entry["algorithm"] == algorithm:
            entry["signature"] = "0" * 64
            break
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_present_invalid_fn_dsa_is_denied_even_when_required_signatures_are_valid() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _component_fn_dsa_signature(receipt)["signature"] = "0" * 64
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_fn_dsa_wrong_key_role_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _component_fn_dsa_signature(receipt)["key_id"] = "test-shield_orchestrator-fn-dsa-v1"
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("trusted key not found",)
    assert result.final_approval is False


@pytest.mark.parametrize("bad_profile", ["fips206-draft-falcon512-v1", "fips204-ml-dsa-65-v1"])
def test_v48h_unsupported_or_flipped_fn_dsa_standard_profile_is_denied(bad_profile: str) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _orchestrator_signature(receipt, FN_DSA)["standard_profile"] = bad_profile

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_fn_dsa_present_requires_matching_trust_registry_key() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    registry = copy.deepcopy(flow["trusted_key_registry"])
    registry["entries"] = [entry for entry in registry["entries"] if entry["algorithm"] != FN_DSA]

    result = verify_shield_v4_orchestrator_receipt(
        flow["receipt"],
        expected_context_hash=flow["expected_context_hash"],
        expected_request_id=flow["expected_request_id"],
        trusted_key_registry=registry,
        verification_time=flow["verification_time"],
        signature_verifier=_verify_test_only_signature,
    )

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.dominant_reason_ids == ("trusted key not found",)
    assert result.final_approval is False


def test_v48h_duplicate_fn_dsa_entry_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    receipt["signature_bundle"]["signatures"].append(copy.deepcopy(_orchestrator_signature(receipt, FN_DSA)))

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_fn_dsa_cross_receipt_or_cross_role_splice_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _component_fn_dsa_signature(receipt)["signature"] = _orchestrator_signature(receipt, FN_DSA)["signature"]
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_component_signature_results_cannot_falsely_claim_or_hide_fn_dsa() -> None:
    no_fn_flow = _load_flow_fixture("full_multi_repo_v4_allow_flow.json")
    claimed = copy.deepcopy(no_fn_flow["receipt"])
    claimed["component_signature_results"][0]["verified_algorithms"] = ["classical-ed25519", ML_DSA, FN_DSA]
    claimed["component_signature_results"][0]["verified_standard_profiles"] = [
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["classical-ed25519"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[ML_DSA],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[FN_DSA],
    ]
    _resign_orchestrator_receipt(claimed)
    claimed_result = _verify_flow(no_fn_flow, claimed)
    assert claimed_result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY
    assert claimed_result.dominant_reason_ids == ("component signature result mismatch",)

    fn_flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    hidden = copy.deepcopy(fn_flow["receipt"])
    hidden["component_signature_results"][0]["verified_algorithms"] = ["classical-ed25519", ML_DSA]
    hidden["component_signature_results"][0]["verified_standard_profiles"] = [
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["classical-ed25519"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[ML_DSA],
    ]
    _resign_orchestrator_receipt(hidden)
    hidden_result = _verify_flow(fn_flow, hidden)
    assert hidden_result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_POLICY
    assert hidden_result.dominant_reason_ids == ("component signature result mismatch",)
    assert hidden_result.final_approval is False


def test_v48h_e_component_signature_result_duplicate_algorithm_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    receipt["component_signature_results"][0]["verified_algorithms"].append(ML_DSA)
    receipt["component_signature_results"][0]["verified_standard_profiles"].append(
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[ML_DSA]
    )
    with pytest.raises(ShieldV4ReceiptContractError, match="unique"):
        _validate_component_signature_results(receipt["component_signature_results"])
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_e_component_signature_result_profile_mismatch_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    receipt["component_signature_results"][0]["verified_standard_profiles"] = [
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["classical-ed25519"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[ML_DSA],
        "fips206-final-falcon1024-v1",
    ]
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_e_component_signature_result_profile_omission_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    receipt["component_signature_results"][0]["verified_standard_profiles"] = [
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM["classical-ed25519"],
        DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[ML_DSA],
    ]
    _resign_orchestrator_receipt(receipt)

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_fn_dsa_different_payload_hash_is_denied() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    _orchestrator_signature(receipt, FN_DSA)["signed_payload_hash"] = hashlib.sha256(b"different-receipt").hexdigest()

    result = _verify_flow(flow, receipt)

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_TAMPERED_RECEIPT
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False


def test_v48h_profile_and_component_result_private_edges_are_fail_closed() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])

    assert default_standard_profile_for_algorithm(FN_DSA) == FN_DSA_PROFILE
    with pytest.raises(ShieldV4ReceiptContractError, match="unsupported Shield v4 signature algorithm"):
        default_standard_profile_for_algorithm("pqc-falcon")

    unsupported_component_result = copy.deepcopy(receipt)
    unsupported_component_result["component_signature_results"][0]["verified_algorithms"] = [
        "classical-ed25519",
        ML_DSA,
        "pqc-falcon",
    ]
    _resign_orchestrator_receipt(unsupported_component_result)
    unsupported_result = _verify_flow(flow, unsupported_component_result)
    assert unsupported_result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert unsupported_result.final_approval is False

    registry = load_trusted_shield_v4_key_registry(flow["trusted_key_registry"])
    bad_profile_bundle = copy.deepcopy(receipt["signature_bundle"])
    for entry in bad_profile_bundle["signatures"]:
        if entry["algorithm"] == FN_DSA:
            entry["standard_profile"] = "fips206-draft-falcon512-v1"
            break
    with pytest.raises(_VerifierRejection, match="unsupported Shield v4 signature standard_profile"):
        _verify_bundle(
            bad_profile_bundle,
            expected_signed_payload_hash=receipt["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ORCHESTRATOR_ROLE,
            registry=registry,
            verification_time=flow["verification_time"],
            artifact_not_before=receipt["not_before"],
            artifact_not_after=receipt["not_after"],
            signature_verifier=_verify_test_only_signature,
        )

    with pytest.raises(_VerifierRejection, match="component signature result mismatch"):
        _normalise_component_signature_result(
            {
                "component_id": "adn",
                "component_role": COMPONENT_ROLES["adn"],
                "verified": True,
                "verified_algorithms": "classical-ed25519",
                "signature_policy": "policy.v1",
            }
        )

    assert KEY_REGISTRY_SCHEMA_VERSION == flow["trusted_key_registry"]["schema_version"]


@pytest.mark.parametrize("bundle_target", ("orchestrator", "component"))
@pytest.mark.parametrize("algorithm_sequence", NONCANONICAL_SIGNATURE_SEQUENCES)
def test_v49j_adamantineos_rejects_noncanonical_receipt_and_component_order_before_trust_or_crypto(
    bundle_target: str,
    algorithm_sequence: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    receipt = copy.deepcopy(flow["receipt"])
    if bundle_target == "orchestrator":
        bundle = receipt["signature_bundle"]
    else:
        bundle = receipt["component_verdicts"][-1]["signature_bundle"]
    bundle["signatures"] = _ordered_signatures(
        bundle["signatures"],
        algorithm_sequence,
    )
    if bundle_target == "component":
        _resign_orchestrator_receipt(receipt)

    calls = {"trust": 0, "crypto": 0}

    def forbidden_key_lookup(*_args, **_kwargs):
        calls["trust"] += 1
        raise AssertionError("trust lookup must not run before whole-receipt preflight")

    def forbidden_crypto(_entry, _key):
        calls["crypto"] += 1
        raise AssertionError("crypto must not run before whole-receipt preflight")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key_lookup)
    result = verify_shield_v4_orchestrator_receipt(
        receipt,
        expected_context_hash=flow["expected_context_hash"],
        expected_request_id=flow["expected_request_id"],
        trusted_key_registry=flow["trusted_key_registry"],
        verification_time=flow["verification_time"],
        signature_verifier=forbidden_crypto,
    )

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    assert result.final_approval is False
    assert calls == {"trust": 0, "crypto": 0}


@pytest.mark.parametrize("algorithm_sequence", NONCANONICAL_SIGNATURE_SEQUENCES)
def test_v49j_direct_bundle_verifier_rejects_noncanonical_order_before_trust_or_crypto(
    algorithm_sequence: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    bundle = copy.deepcopy(flow["receipt"]["signature_bundle"])
    bundle["signatures"] = _ordered_signatures(
        bundle["signatures"],
        algorithm_sequence,
    )
    calls = {"trust": 0, "crypto": 0}

    def forbidden_key_lookup(*_args, **_kwargs):
        calls["trust"] += 1
        raise AssertionError("trust lookup must not run before bundle preflight")

    def forbidden_crypto(_entry, _key):
        calls["crypto"] += 1
        raise AssertionError("crypto must not run before bundle preflight")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key_lookup)
    with pytest.raises(_VerifierRejection, match="canonical policy order"):
        _verify_direct_orchestrator_bundle(
            flow=flow,
            bundle=bundle,
            signature_verifier=forbidden_crypto,
        )

    assert calls == {"trust": 0, "crypto": 0}


@pytest.mark.parametrize("algorithm_sequence", MISSING_REQUIRED_SIGNATURE_SEQUENCES)
def test_v49j_direct_bundle_verifier_rejects_missing_required_before_trust_or_crypto(
    algorithm_sequence: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    bundle = copy.deepcopy(flow["receipt"]["signature_bundle"])
    bundle["signatures"] = _ordered_signatures(
        bundle["signatures"],
        algorithm_sequence,
    )
    calls = {"trust": 0, "crypto": 0}

    def forbidden_key_lookup(*_args, **_kwargs):
        calls["trust"] += 1
        raise AssertionError("trust lookup must not run before bundle preflight")

    def forbidden_crypto(_entry, _key):
        calls["crypto"] += 1
        raise AssertionError("crypto must not run before bundle preflight")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key_lookup)
    with pytest.raises(_VerifierRejection, match="policy requirements"):
        _verify_direct_orchestrator_bundle(
            flow=flow,
            bundle=bundle,
            signature_verifier=forbidden_crypto,
        )

    assert calls == {"trust": 0, "crypto": 0}


@pytest.mark.parametrize(
    "defect",
    (
        "bundle_not_mapping",
        "bundle_snapshot_error",
        "bundle_fields",
        "bundle_schema",
        "bundle_policy",
        "empty_signatures",
        "signature_list_snapshot_error",
        "invalid_expected_hash",
        "entry_not_mapping",
        "entry_snapshot_error",
        "entry_fields",
        "unsupported_algorithm",
        "duplicate_algorithm",
        "duplicate_key",
        "invalid_entry_hash",
        "mismatched_hash",
        "invalid_signature_encoding",
        "wrong_domain",
        "wrong_profile",
        "empty_key_id",
        "invalid_key_version",
    ),
)
def test_v49j_direct_bundle_verifier_completes_structural_preflight_before_trust_or_crypto(
    defect: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    bundle: Any = copy.deepcopy(flow["receipt"]["signature_bundle"])
    bundle["signatures"] = bundle["signatures"][:2]
    expected_hash: str | None = None
    if defect == "bundle_not_mapping":
        bundle = []
    elif defect == "bundle_snapshot_error":
        bundle = _ExplodingMapping(bundle)
    elif defect == "bundle_fields":
        bundle["extra"] = True
    elif defect == "bundle_schema":
        bundle["schema_version"] = "wrong"
    elif defect == "bundle_policy":
        bundle["policy_version"] = "policy.weak"
    elif defect == "empty_signatures":
        bundle["signatures"] = []
    elif defect == "signature_list_snapshot_error":
        bundle["signatures"] = _ExplodingList(bundle["signatures"])
    elif defect == "invalid_expected_hash":
        expected_hash = "bad"
    elif defect == "entry_not_mapping":
        bundle["signatures"][1] = "bad"
    elif defect == "entry_snapshot_error":
        bundle["signatures"][1] = _ExplodingMapping(bundle["signatures"][1])
    elif defect == "entry_fields":
        bundle["signatures"][1].pop("signature")
    elif defect == "unsupported_algorithm":
        bundle["signatures"][1]["algorithm"] = "unknown"
    elif defect == "duplicate_algorithm":
        bundle["signatures"][1]["algorithm"] = "classical-ed25519"
    elif defect == "duplicate_key":
        bundle["signatures"][1]["key_id"] = bundle["signatures"][0]["key_id"]
        bundle["signatures"][1]["key_version"] = bundle["signatures"][0]["key_version"]
    elif defect == "invalid_entry_hash":
        bundle["signatures"][1]["signed_payload_hash"] = "bad"
    elif defect == "mismatched_hash":
        bundle["signatures"][1]["signed_payload_hash"] = "0" * 64
    elif defect == "invalid_signature_encoding":
        bundle["signatures"][1]["signature"] = "bad"
    elif defect == "wrong_domain":
        bundle["signatures"][1]["domain_tag"] = COMPONENT_VERDICT_DOMAIN
    elif defect == "wrong_profile":
        bundle["signatures"][1]["standard_profile"] = FN_DSA_PROFILE
    elif defect == "empty_key_id":
        bundle["signatures"][1]["key_id"] = ""
    elif defect == "invalid_key_version":
        bundle["signatures"][1]["key_version"] = False

    calls = {"trust": 0, "crypto": 0}

    def forbidden_key_lookup(*_args, **_kwargs):
        calls["trust"] += 1
        raise AssertionError("trust lookup must not run before bundle preflight")

    def forbidden_crypto(_entry, _key):
        calls["crypto"] += 1
        raise AssertionError("crypto must not run before bundle preflight")

    monkeypatch.setattr(verifier_module, "_find_key", forbidden_key_lookup)
    with pytest.raises(_VerifierRejection):
        _verify_direct_orchestrator_bundle(
            flow=flow,
            bundle=bundle,
            signature_verifier=forbidden_crypto,
            expected_signed_payload_hash=expected_hash,
        )

    assert calls == {"trust": 0, "crypto": 0}


def test_v49j_direct_bundle_verifier_uses_preflight_snapshots_during_crypto() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    bundle = copy.deepcopy(flow["receipt"]["signature_bundle"])
    calls = 0

    def mutating_verifier(entry, key):
        nonlocal calls
        calls += 1
        if calls == 1:
            bundle["signatures"][1]["signature"] = "0" * 64
        return _verify_test_only_signature(entry, key)

    summary = _verify_direct_orchestrator_bundle(
        flow=flow,
        bundle=bundle,
        signature_verifier=mutating_verifier,
    )

    assert summary["verified_algorithms"] == ["classical-ed25519", ML_DSA, FN_DSA]
    assert calls == 3
    assert bundle["signatures"][1]["signature"] == "0" * 64


def test_v49j_direct_bundle_verifier_snapshots_stateful_mapping_before_validation() -> None:
    flow = _load_flow_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")
    bundle = copy.deepcopy(flow["receipt"]["signature_bundle"])
    valid_entry = copy.deepcopy(bundle["signatures"][1])
    flipped_entry = copy.deepcopy(valid_entry)
    flipped_entry["signed_payload_hash"] = "0" * 64
    flipped_entry["domain_tag"] = COMPONENT_VERDICT_DOMAIN
    flipped_entry["signature"] = "0" * 64
    stateful_entry = _FlipAfterFirstSnapshotMapping(valid_entry, flipped_entry)
    bundle["signatures"][1] = stateful_entry
    observed_entries: list[dict[str, Any]] = []

    def observing_verifier(entry, key):
        observed_entries.append(dict(entry))
        return _verify_test_only_signature(entry, key)

    summary = _verify_direct_orchestrator_bundle(
        flow=flow,
        bundle=bundle,
        signature_verifier=observing_verifier,
    )

    assert summary["verified_algorithms"] == ["classical-ed25519", ML_DSA, FN_DSA]
    assert observed_entries[1]["signed_payload_hash"] == flow["receipt"]["signed_payload_hash"]
    assert observed_entries[1]["domain_tag"] == ORCHESTRATOR_RECEIPT_DOMAIN
    assert stateful_entry["signed_payload_hash"] == "0" * 64
    assert stateful_entry["domain_tag"] == COMPONENT_VERDICT_DOMAIN
