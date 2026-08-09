from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    CANONICALIZATION_PROFILE,
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    ShieldV4ReceiptAuthorityBypassError,
    ShieldV4ReceiptContractError,
    ShieldV4ReceiptDowngradeError,
    ShieldV4ReceiptHashMismatchError,
    _contains_forbidden_authority,
    _expected_final_outcome,
    _require_hash,
    _require_non_empty_str,
    _require_positive_int,
    _require_signature_encoding,
    _require_str_list,
    _validate_component_signature_results,
    _validate_signature_bundle_shape,
    receipt_hash,
    signed_payload_hash,
    to_canonical_json,
    unsigned_receipt_payload,
    validate_component_verdict_contract,
    validate_shield_v4_receipt_contract,
)

FIXTURES = Path(__file__).resolve().parents[2] / "src" / "adamantine" / "v1" / "fixtures" / "shield_v4"
CTX = "a" * 64
NONCANONICAL_SIGNATURE_SEQUENCES = (
    ("ml-dsa", "classical-ed25519"),
    ("fn-dsa", "classical-ed25519", "ml-dsa"),
    ("fn-dsa", "ml-dsa", "classical-ed25519"),
    ("classical-ed25519", "fn-dsa", "ml-dsa"),
    ("ml-dsa", "classical-ed25519", "fn-dsa"),
    ("ml-dsa", "fn-dsa", "classical-ed25519"),
)


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def mutate_receipt(name: str, mutator):
    payload = copy.deepcopy(load_fixture(name))
    mutator(payload)
    return payload


def test_shield_v4_accepts_valid_allow_fixture_contract_boundary() -> None:
    receipt = validate_shield_v4_receipt_contract(load_fixture("valid_allow_signed_receipt.json"), expected_context_hash=CTX)

    assert receipt["schema_version"] == "shield.receipt.v2"
    assert receipt["contract_version"] == 4
    assert receipt["canonicalization_profile"] == CANONICALIZATION_PROFILE
    assert receipt["signature_policy"] == "policy.v1"
    assert receipt["final_outcome"] == "ALLOW"
    assert receipt["adamantineos_handoff"]["handoff_allowed"] is True
    assert "verification_summary" in receipt

    unsigned = unsigned_receipt_payload(receipt)
    assert receipt_hash(unsigned) == receipt["receipt_hash"]
    assert signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned) == receipt["signed_payload_hash"]

    component = receipt["component_verdicts"][0]
    checked_component = validate_component_verdict_contract(component, expected_context_hash=CTX)
    component_unsigned = {
        key: checked_component[key]
        for key in checked_component
        if key not in {"signed_payload_hash", "signature_bundle", "verification_summary"}
    }
    assert signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=component_unsigned) == component["signed_payload_hash"]


def test_shield_v4_accepts_valid_deny_fixture_without_granting_execution_authority() -> None:
    receipt = validate_shield_v4_receipt_contract(load_fixture("deny_signed_receipt.json"), expected_context_hash=CTX)

    assert receipt["final_outcome"] == "DENY"
    assert receipt["adamantineos_handoff"]["handoff_allowed"] is False


def test_shield_v4_rejects_downgrade_and_tampered_signature_fixtures() -> None:
    with pytest.raises(ShieldV4ReceiptDowngradeError, match="Shield v3"):
        validate_shield_v4_receipt_contract(load_fixture("v3_downgrade_rejected.json"), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="signature"):
        validate_shield_v4_receipt_contract(load_fixture("tampered_signature_deny.json"), expected_context_hash=CTX)


def test_shield_v4_contract_rejects_non_dict_and_bad_schema_fields() -> None:
    with pytest.raises(ShieldV4ReceiptContractError, match="receipt must be dict"):
        validate_shield_v4_receipt_contract(["bad"], expected_context_hash=CTX)  # type: ignore[arg-type]

    with pytest.raises(ShieldV4ReceiptContractError, match="schema"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.pop("request_id")), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="schema mismatch"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("schema_version", "shield.receipt.v9")), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="contract mismatch"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("contract_version", 5)), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="fail_closed"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("fail_closed", False)), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="canonicalization profile"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("canonicalization_profile", "wrong")), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="signature policy"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("signature_policy", "policy.weak")), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="unsupported final outcome"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("final_outcome", "MAYBE")), expected_context_hash=CTX)


def test_shield_v4_contract_rejects_context_and_receipt_hash_mismatches() -> None:
    with pytest.raises(ShieldV4ReceiptContractError, match="context mismatch"):
        validate_shield_v4_receipt_contract(load_fixture("valid_allow_signed_receipt.json"), expected_context_hash="b" * 64)

    with pytest.raises(ShieldV4ReceiptHashMismatchError, match="receipt hash"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("receipt_hash", "0" * 64)), expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptHashMismatchError, match="signed payload"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("signed_payload_hash", "0" * 64)), expected_context_hash=CTX)


def test_shield_v4_contract_rejects_bad_receipt_scalar_fields() -> None:
    cases = [
        ("request_id", "", "request_id"),
        ("freshness_nonce", "", "freshness_nonce"),
        ("not_before", "", "not_before"),
        ("not_after", "", "not_after"),
        ("key_registry_version", True, "key_registry_version"),
        ("dominant_reason_ids", [], "dominant_reason_ids"),
        ("adamantineos_handoff", [], "adamantineos_handoff"),
    ]
    for field, value, message in cases:
        with pytest.raises(ShieldV4ReceiptContractError, match=message):
            validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r, f=field, v=value: r.__setitem__(f, v)), expected_context_hash=CTX)


def test_shield_v4_contract_rejects_handoff_authority_and_non_allow_handoff_true() -> None:
    with pytest.raises(ShieldV4ReceiptAuthorityBypassError, match="forbidden authority"):
        validate_shield_v4_receipt_contract(
            mutate_receipt("valid_allow_signed_receipt.json", lambda r: r["adamantineos_handoff"].__setitem__("final_approval", True)),
            expected_context_hash=CTX,
        )

    with pytest.raises(ShieldV4ReceiptAuthorityBypassError, match="non-ALLOW"):
        validate_shield_v4_receipt_contract(
            mutate_receipt("deny_signed_receipt.json", lambda r: r["adamantineos_handoff"].__setitem__("handoff_allowed", True)),
            expected_context_hash=CTX,
        )


def test_shield_v4_contract_rejects_component_result_errors() -> None:
    bad_length = mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("component_signature_results", r["component_signature_results"][:-1]))
    with pytest.raises(ShieldV4ReceiptContractError, match="component_signature_results"):
        validate_shield_v4_receipt_contract(bad_length, expected_context_hash=CTX)

    cases = [
        (lambda result: result.__setitem__("component_id", "unknown"), "unknown component"),
        (lambda result: (result.__setitem__("component_id", "dqsn"), result.__setitem__("component_role", "shield_component_dqsn")), "duplicate"),
        (lambda result: result.__setitem__("component_role", "wrong"), "role mismatch"),
        (lambda result: result.__setitem__("verified", False), "must be verified"),
        (lambda result: result.__setitem__("signature_policy", "policy.weak"), "policy mismatch"),
        (lambda result: result.__setitem__("verified_algorithms", ["classical-ed25519"]), "missing required algorithm"),
        (lambda result: result.pop("verified"), "fields"),
    ]
    for mutator, message in cases:
        receipt = load_fixture("valid_allow_signed_receipt.json")
        mutator(receipt["component_signature_results"][0])
        with pytest.raises(ShieldV4ReceiptContractError, match=message):
            validate_shield_v4_receipt_contract(receipt, expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="must be dict"):
        _validate_component_signature_results(["bad"] * 5)


def test_shield_v4_contract_rejects_component_verdict_errors() -> None:
    with pytest.raises(ShieldV4ReceiptContractError, match="component_verdicts"):
        validate_shield_v4_receipt_contract(mutate_receipt("valid_allow_signed_receipt.json", lambda r: r.__setitem__("component_verdicts", [])), expected_context_hash=CTX)

    bad_unknown = load_fixture("valid_allow_signed_receipt.json")
    bad_unknown["component_verdicts"][0]["component_id"] = "unknown"
    with pytest.raises(ShieldV4ReceiptContractError, match="unsupported"):
        validate_shield_v4_receipt_contract(bad_unknown, expected_context_hash=CTX)

    bad_duplicate = load_fixture("valid_allow_signed_receipt.json")
    bad_duplicate["component_verdicts"][0] = copy.deepcopy(bad_duplicate["component_verdicts"][1])
    with pytest.raises(ShieldV4ReceiptContractError, match="duplicate component verdict"):
        validate_shield_v4_receipt_contract(bad_duplicate, expected_context_hash=CTX)

    with pytest.raises(ShieldV4ReceiptContractError, match="component verdict must be dict"):
        validate_component_verdict_contract(["bad"], expected_context_hash=CTX)  # type: ignore[arg-type]

    component_cases = [
        (lambda c: c.pop("request_id"), "fields"),
        (lambda c: c.__setitem__("contract_version", 5), "contract mismatch"),
        (lambda c: c.__setitem__("schema_version", "shield.verdict.v9"), "schema mismatch"),
        (lambda c: c.__setitem__("fail_closed", False), "fail_closed"),
        (lambda c: c.__setitem__("canonicalization_profile", "wrong"), "canonicalization"),
        (lambda c: c.__setitem__("signature_policy", "wrong"), "signature policy"),
        (lambda c: c.__setitem__("decision", "MAYBE"), "unsupported component decision"),
        (lambda c: c.__setitem__("context_hash", "b" * 64), "context_hash mismatch"),
        (lambda c: c.__setitem__("request_id", ""), "request_id"),
        (lambda c: c.__setitem__("freshness_nonce", ""), "freshness_nonce"),
        (lambda c: c.__setitem__("not_before", ""), "not_before"),
        (lambda c: c.__setitem__("not_after", ""), "not_after"),
        (lambda c: c.__setitem__("evidence_hash", "x"), "evidence_hash"),
        (lambda c: c.__setitem__("reason_ids", []), "reason_ids"),
        (lambda c: c.__setitem__("evidence_families", []), "evidence_families"),
        (lambda c: c.__setitem__("key_registry_version", 0), "key_registry_version"),
        (lambda c: c.__setitem__("metadata", []), "metadata"),
        (lambda c: c["metadata"].__setitem__("override", True), "forbidden authority"),
        (lambda c: c.__setitem__("signed_payload_hash", "0" * 64), "signed payload hash"),
    ]
    for mutator, message in component_cases:
        component = copy.deepcopy(load_fixture("valid_allow_signed_receipt.json")["component_verdicts"][0])
        mutator(component)
        with pytest.raises((ShieldV4ReceiptContractError, ShieldV4ReceiptHashMismatchError, ShieldV4ReceiptAuthorityBypassError), match=message):
            validate_component_verdict_contract(component, expected_context_hash=CTX)


def test_shield_v4_contract_rejects_signature_bundle_shape_and_policy_errors() -> None:
    receipt = load_fixture("valid_allow_signed_receipt.json")
    expected_hash = receipt["signed_payload_hash"]
    bundle = receipt["signature_bundle"]

    bundle_cases = [
        ("bad", "signature bundle must be dict"),
        ({"schema_version": "shield.signature_bundle.v1"}, "fields"),
        ({**bundle, "schema_version": "wrong"}, "schema mismatch"),
        ({**bundle, "policy_version": "policy.weak"}, "policy mismatch"),
        ({**bundle, "signatures": []}, "non-empty"),
        ({**bundle, "signatures": ["bad"]}, "signature entry must be dict"),
        ({**bundle, "signatures": [{"algorithm": "ml-dsa"}]}, "entry fields"),
    ]
    for bad_bundle, message in bundle_cases:
        with pytest.raises(ShieldV4ReceiptContractError, match=message):
            _validate_signature_bundle_shape(bad_bundle, expected_signed_payload_hash=expected_hash, expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN)

    entry_cases = [
        (lambda e: e.__setitem__("algorithm", "unknown"), "unsupported"),
        (lambda e: e.__setitem__("key_id", ""), "key_id"),
        (lambda e: e.__setitem__("key_version", False), "key_version"),
        (lambda e: e.__setitem__("signed_payload_hash", "0" * 64), "signed_payload_hash mismatch"),
        (lambda e: e.__setitem__("domain_tag", COMPONENT_VERDICT_DOMAIN), "domain tag mismatch"),
        (lambda e: e.__setitem__("signature", "x"), "signature"),
    ]
    for mutator, message in entry_cases:
        bad_bundle = copy.deepcopy(bundle)
        mutator(bad_bundle["signatures"][0])
        with pytest.raises((ShieldV4ReceiptContractError, ShieldV4ReceiptHashMismatchError), match=message):
            _validate_signature_bundle_shape(bad_bundle, expected_signed_payload_hash=expected_hash, expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN)

    b64u_bundle = copy.deepcopy(bundle)
    b64u_bundle["signatures"][0]["signature"] = "b64u:YWJj"
    assert _validate_signature_bundle_shape(
        b64u_bundle,
        expected_signed_payload_hash=expected_hash,
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
    )["signatures"][0]["signature"] == "b64u:YWJj"

    duplicate_algo = copy.deepcopy(bundle)
    duplicate_algo["signatures"][1]["algorithm"] = duplicate_algo["signatures"][0]["algorithm"]
    with pytest.raises(ShieldV4ReceiptContractError, match="duplicate"):
        _validate_signature_bundle_shape(duplicate_algo, expected_signed_payload_hash=expected_hash, expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN)

    missing_required = copy.deepcopy(bundle)
    missing_required["signatures"] = [missing_required["signatures"][0]]
    with pytest.raises(ShieldV4ReceiptContractError, match="policy requirements"):
        _validate_signature_bundle_shape(missing_required, expected_signed_payload_hash=expected_hash, expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN)


@pytest.mark.parametrize("algorithm_sequence", NONCANONICAL_SIGNATURE_SEQUENCES)
def test_v49j_contract_rejects_noncanonical_signature_bundle_order(
    algorithm_sequence: tuple[str, ...],
) -> None:
    if len(algorithm_sequence) == 2:
        receipt = load_fixture("valid_allow_signed_receipt.json")
    else:
        receipt = load_fixture("full_multi_repo_v4_fn_dsa_allow_flow.json")["receipt"]
    bundle = copy.deepcopy(receipt["signature_bundle"])
    signatures_by_algorithm = {
        entry["algorithm"]: entry for entry in bundle["signatures"]
    }
    bundle["signatures"] = [
        signatures_by_algorithm[algorithm] for algorithm in algorithm_sequence
    ]

    with pytest.raises(ShieldV4ReceiptContractError, match="canonical policy order"):
        _validate_signature_bundle_shape(
            bundle,
            expected_signed_payload_hash=receipt["signed_payload_hash"],
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        )


def test_shield_v4_contract_rejects_final_outcome_and_component_set_mismatches() -> None:
    with pytest.raises(ShieldV4ReceiptContractError, match="final outcome"):
        validate_shield_v4_receipt_contract(mutate_receipt("deny_signed_receipt.json", lambda r: r.__setitem__("final_outcome", "ALLOW")), expected_context_hash=CTX)

    mismatch = load_fixture("valid_allow_signed_receipt.json")
    mismatch["component_signature_results"][0]["component_id"] = "dqsn"
    mismatch["component_signature_results"][0]["component_role"] = "shield_component_dqsn"
    with pytest.raises(ShieldV4ReceiptContractError, match="duplicate"):
        validate_shield_v4_receipt_contract(mismatch, expected_context_hash=CTX)


def test_shield_v4_canonicalization_rejects_ambiguous_payloads() -> None:
    assert to_canonical_json({"b": 1, "a": True}) == '{"a":true,"b":1}'
    assert to_canonical_json({"tuple": ("ok", 1)}) == '{"tuple":["ok",1]}'
    with pytest.raises(ShieldV4ReceiptContractError, match="payload must be dict"):
        to_canonical_json(["bad"])  # type: ignore[arg-type]
    with pytest.raises(ShieldV4ReceiptContractError, match="null"):
        to_canonical_json({"bad": None})
    with pytest.raises(ShieldV4ReceiptContractError, match="floats"):
        to_canonical_json({"bad": 1.5})
    with pytest.raises(ShieldV4ReceiptContractError, match="object keys"):
        to_canonical_json({1: "bad"})  # type: ignore[dict-item]
    with pytest.raises(ShieldV4ReceiptContractError, match="duplicate key"):
        to_canonical_json({"\u00e9": 1, "e\u0301": 2})
    with pytest.raises(ShieldV4ReceiptContractError, match="unsupported type"):
        to_canonical_json({"bad": object()})
    with pytest.raises(ShieldV4ReceiptContractError, match="unsupported Shield v4 domain tag"):
        signed_payload_hash(domain_tag="wrong", payload={})


def test_shield_v4_helper_guards_are_fail_closed() -> None:
    assert _contains_forbidden_authority({"nested": [{"execute": True}]}) is True
    assert _contains_forbidden_authority({"nested": ["safe"]}) is False
    assert _expected_final_outcome([{"decision": "ALLOW"}]) == "ALLOW"
    assert _expected_final_outcome([{"decision": "ESCALATE"}]) == "HUMAN_REVIEW_REQUIRED"
    assert _expected_final_outcome([{"decision": "ERROR"}]) == "DENY"

    with pytest.raises(ShieldV4ReceiptContractError, match="name"):
        _require_non_empty_str("", field="name")
    with pytest.raises(ShieldV4ReceiptContractError, match="number"):
        _require_positive_int(-1, field="number")
    with pytest.raises(ShieldV4ReceiptContractError, match="64-character"):
        _require_hash("0", field="hash")
    with pytest.raises(ShieldV4ReceiptContractError, match="sha256 hex"):
        _require_hash("g" * 64, field="hash")
    with pytest.raises(ShieldV4ReceiptContractError, match="lowercase"):
        _require_hash("A" * 64, field="hash")
    assert _require_signature_encoding("0" * 64, field="signature") == "0" * 64
    assert _require_signature_encoding("b64u:YWJj", field="signature") == "b64u:YWJj"
    with pytest.raises(ShieldV4ReceiptContractError, match="non-empty"):
        _require_signature_encoding("b64u:", field="signature")
    with pytest.raises(ShieldV4ReceiptContractError, match="unpadded"):
        _require_signature_encoding("b64u:YWJj=", field="signature")
    with pytest.raises(ShieldV4ReceiptContractError, match="invalid"):
        _require_signature_encoding("b64u:****", field="signature")
    with pytest.raises(ShieldV4ReceiptContractError, match="invalid"):
        _require_signature_encoding("b64u:A", field="signature")
    with pytest.raises(ShieldV4ReceiptContractError, match="64-character"):
        _require_signature_encoding("not-b64u", field="signature")
    with pytest.raises(ShieldV4ReceiptContractError, match="list"):
        _require_str_list("bad", field="items")  # type: ignore[arg-type]
    with pytest.raises(ShieldV4ReceiptContractError, match="entry"):
        _require_str_list([""], field="items")
    with pytest.raises(ShieldV4ReceiptContractError, match="unique"):
        _require_str_list(["x", "x"], field="items")
    assert _require_str_list([], field="optional", allow_empty=True) == []
