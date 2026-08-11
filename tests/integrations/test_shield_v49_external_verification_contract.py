from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    ShieldV4ReceiptVerificationResult,
    ShieldV4ReceiptVerificationState,
    _verify_test_only_signature,
    verify_shield_v4_orchestrator_receipt,
)
from adamantine.v1.policy.final_policy_engine import (
    FinalPolicyEngineState,
    LocalPolicyGateResult,
    evaluate_final_policy_engine,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = (
    ROOT
    / "src"
    / "adamantine"
    / "v1"
    / "fixtures"
    / "shield_v4"
    / "external_verifier_contract_v1_kat.json"
)
FIXTURE_SHA256 = "308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f"
CANONICAL_ALGORITHMS = ["classical-ed25519", "ml-dsa", "fn-dsa"]


@dataclass(frozen=True)
class _SupportingEvidence:
    state: str = "ALLOW_EVIDENCE_CONTINUE_CHECKS"
    outcome: str = "ALLOW_EVIDENCE"
    reason_id: ReasonId = ReasonId.EVIDENCE_OK
    accepted_as_evidence: bool = True
    verified: bool = True
    final_approval: bool = False
    handoff_allowed: bool = True
    context_hash: str = "a" * 64
    dominant_reason_ids: tuple[str, ...] = (ReasonId.EVIDENCE_OK.value,)
    final_outcome: str = "ALLOW"
    receipt: Mapping[str, Any] | None = None
    verification_summary: Mapping[str, Any] | None = None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _fixture() -> dict[str, Any]:
    return json.loads(
        FIXTURE_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )


def _verify(
    fixture: dict[str, Any],
    *,
    receipt: dict[str, Any] | None = None,
    **overrides: Any,
) -> ShieldV4ReceiptVerificationResult:
    inputs = fixture["inputs"]
    parameters: dict[str, Any] = {
        "expected_context_hash": inputs["expected_context_hash"],
        "expected_request_id": inputs["expected_request_id"],
        "trusted_key_registry": fixture["verifier_controlled_test_registry"],
        "verification_time": inputs["verification_time"],
        "seen_request_ids": inputs["seen_request_ids"],
        "rejected_receipt_hashes": inputs["rejected_receipt_hashes"],
        "minimum_key_registry_version": inputs["minimum_key_registry_version"],
        "signature_verifier": _verify_test_only_signature,
    }
    parameters.update(overrides)
    return verify_shield_v4_orchestrator_receipt(
        fixture["receipt"] if receipt is None else receipt,
        **parameters,
    )


def _result_contract(result: ShieldV4ReceiptVerificationResult) -> dict[str, Any]:
    return {
        "accepted_as_evidence": result.accepted_as_evidence,
        "dominant_reason_ids": list(result.dominant_reason_ids),
        "final_approval": result.final_approval,
        "final_outcome": result.final_outcome,
        "handoff_allowed": result.handoff_allowed,
        "reason_id": result.reason_id.value,
        "state": result.state.value,
        "verified": result.verified,
    }


def test_v49l_external_fixture_is_the_exact_orchestrator_contract_copy() -> None:
    raw = FIXTURE_PATH.read_bytes()
    fixture = _fixture()

    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256
    assert raw.endswith(b"\n")
    assert b"\r" not in raw
    assert raw.decode("utf-8", errors="strict").isascii()
    assert fixture["author_attribution"] == "DarekDGB"
    assert fixture["schema_version"] == "shield.external_verifier_contract.v1"
    assert fixture["contract_version"] == 1
    assert "trusted_key_registry" not in fixture["receipt"]
    assert "verifier_controlled_test_registry" not in fixture["receipt"]

    bundles = [
        *(component["signature_bundle"] for component in fixture["receipt"]["component_verdicts"]),
        fixture["receipt"]["signature_bundle"],
    ]
    assert all(
        [entry["algorithm"] for entry in bundle["signatures"]]
        == CANONICAL_ALGORITHMS
        for bundle in bundles
    )


def test_v49l_adamantineos_accepts_external_contract_as_evidence_only() -> None:
    fixture = _fixture()
    result = _verify(fixture)

    assert _result_contract(result) == fixture["expected_result"]
    assert result.state == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert result.receipt == fixture["receipt"]
    assert result.verification_summary is not None
    assert result.verification_summary["key_registry_version"] == 1
    assert result.verification_summary["orchestrator"]["verified_algorithms"] == CANONICAL_ALGORITHMS
    assert [
        item["component_id"]
        for item in result.verification_summary["components"]
    ] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert all(
        item["verified_algorithms"] == CANONICAL_ALGORITHMS
        for item in result.verification_summary["components"]
    )
    assert result.final_approval is False


def test_v49l_external_contract_reaches_final_approval_only_after_adamantineos_gates() -> None:
    fixture = _fixture()
    shield = _verify(fixture)
    supporting = _SupportingEvidence()

    def evaluate(*, wallet_policy_passed: bool):
        return evaluate_final_policy_engine(
            shield=shield,
            wsqk_v2=supporting,
            qid=supporting,
            adaptive_core=supporting,
            ai_gateway=supporting,
            replay=LocalPolicyGateResult(
                "replay",
                True,
                ReasonId.EVIDENCE_OK,
            ),
            wallet_policy=LocalPolicyGateResult(
                "wallet_policy",
                wallet_policy_passed,
                (
                    ReasonId.EVIDENCE_OK
                    if wallet_policy_passed
                    else ReasonId.DENY_POLICY
                ),
            ),
            human=LocalPolicyGateResult(
                "human",
                True,
                ReasonId.EVIDENCE_OK,
            ),
            expected_context_hash=fixture["inputs"]["expected_context_hash"],
            shield_v4_required=True,
        )

    allowed = evaluate(wallet_policy_passed=True)
    assert allowed.state == FinalPolicyEngineState.ALLOW_FINAL_ADAMANTINEOS_DECISION
    assert allowed.final_approval is True

    denied = evaluate(wallet_policy_passed=False)
    assert denied.state == FinalPolicyEngineState.DENY_WALLET_POLICY_GATE
    assert denied.final_approval is False
    assert denied.stopped_at == "wallet_policy"


def test_v49l_external_contract_rejects_replay_stale_revoked_rollback_and_denylist() -> None:
    fixture = _fixture()
    inputs = fixture["inputs"]

    replay = _verify(
        fixture,
        seen_request_ids={inputs["expected_request_id"]},
    )
    assert replay.state == ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK

    stale = _verify(fixture, verification_time="2026-06-21T00:06:00Z")
    assert stale.state == ShieldV4ReceiptVerificationState.REJECTED_FRESHNESS_WINDOW

    revoked_registry = copy.deepcopy(fixture["verifier_controlled_test_registry"])
    revoked_registry["entries"][0]["status"] = "revoked"
    revoked = _verify(fixture, trusted_key_registry=revoked_registry)
    assert revoked.state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    rollback = _verify(fixture, minimum_key_registry_version=2)
    assert rollback.state == ShieldV4ReceiptVerificationState.REJECTED_KEY_REGISTRY

    denylisted = _verify(
        fixture,
        rejected_receipt_hashes={fixture["receipt"]["receipt_hash"]},
    )
    assert denylisted.state == ShieldV4ReceiptVerificationState.REJECTED_REPLAY_RISK

    for result in (replay, stale, revoked, rollback, denylisted):
        assert result.verified is False
        assert result.accepted_as_evidence is False
        assert result.final_approval is False


def test_v49l_external_contract_rejects_context_profile_order_and_weakened_policy() -> None:
    fixture = _fixture()

    wrong_context = _verify(fixture, expected_context_hash="b" * 64)
    assert wrong_context.state == ShieldV4ReceiptVerificationState.REJECTED_CONTEXT_MISMATCH

    wrong_profile_receipt = copy.deepcopy(fixture["receipt"])
    wrong_profile_receipt["signature_bundle"]["signatures"][1][
        "standard_profile"
    ] = "fips204-ml-dsa-44-v1"
    wrong_profile = _verify(fixture, receipt=wrong_profile_receipt)
    assert wrong_profile.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    reordered_receipt = copy.deepcopy(fixture["receipt"])
    reordered_signatures = reordered_receipt["signature_bundle"]["signatures"]
    reordered_signatures[0], reordered_signatures[1] = (
        reordered_signatures[1],
        reordered_signatures[0],
    )
    reordered = _verify(fixture, receipt=reordered_receipt)
    assert reordered.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    weakened_receipt = copy.deepcopy(fixture["receipt"])
    weakened_receipt["signature_bundle"]["policy_version"] = "policy.v0"
    weakened = _verify(fixture, receipt=weakened_receipt)
    assert weakened.state == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT

    for result in (wrong_context, wrong_profile, reordered, weakened):
        assert result.verified is False
        assert result.accepted_as_evidence is False
        assert result.final_approval is False


def test_v49l_external_contract_registry_is_verifier_controlled_only() -> None:
    fixture = _fixture()

    receipt_supplied_registry = copy.deepcopy(fixture["receipt"])
    receipt_supplied_registry["trusted_key_registry"] = copy.deepcopy(
        fixture["verifier_controlled_test_registry"]
    )
    rejected_embedded_registry = _verify(
        fixture,
        receipt=receipt_supplied_registry,
    )
    assert (
        rejected_embedded_registry.state
        == ShieldV4ReceiptVerificationState.REJECTED_INVALID_RECEIPT
    )

    verifier_registry = copy.deepcopy(fixture["verifier_controlled_test_registry"])
    verifier_registry["entries"][0]["public_key"] = "UNTRUSTED-EXTERNAL-KEY"
    rejected_untrusted_key = _verify(
        fixture,
        trusted_key_registry=verifier_registry,
    )
    assert (
        rejected_untrusted_key.state
        == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    )

    for result in (rejected_embedded_registry, rejected_untrusted_key):
        assert result.verified is False
        assert result.accepted_as_evidence is False
        assert result.final_approval is False
