from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOCS = (
    "docs/ADAMANTINEOS_SHIELD_V4_PQC_VERIFIER.md",
    "docs/ADAMANTINEOS_SHIELD_V4_THREAT_MODEL.md",
    "docs/ADAMANTINEOS_SHIELD_V4_TEST_MATRIX.md",
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_shield_v4_adamantineos_docs_exist_and_use_darekdgb_attribution() -> None:
    for path in DOCS:
        content = read(path)
        assert "Author attribution: DarekDGB" in content
        assert "AdamantineOS" in content
        assert "Shield v4" in content


def test_shield_v4_docs_lock_final_boundary_and_no_consensus_authority() -> None:
    combined = "\n".join(read(path) for path in DOCS)

    required_phrases = [
        "AdamantineOS remains the final execution boundary",
        "Shield v4 produces cryptographically verifiable decision evidence only",
        "does not sign transactions",
        "does not broadcast transactions",
        "does not change DigiByte consensus",
        "handoff_allowed` is evidence only",
        "not final approval",
    ]
    for phrase in required_phrases:
        assert phrase in combined


def test_shield_v4_docs_lock_pqc_algorithm_wording() -> None:
    combined = "\n".join(read(path) for path in DOCS)

    assert "ML-DSA, formerly CRYSTALS-Dilithium" in combined
    assert "FN-DSA, based on Falcon" in combined
    assert "FN-DSA/Falcon is separate from ML-DSA" in combined
    assert "fn-dsa` is optional evidence only" in combined


def test_shield_v4_docs_lock_required_files_and_tests() -> None:
    verifier_doc = read("docs/ADAMANTINEOS_SHIELD_V4_PQC_VERIFIER.md")
    test_matrix = read("docs/ADAMANTINEOS_SHIELD_V4_TEST_MATRIX.md")

    required_paths = [
        "src/adamantine/v1/contracts/shield_orchestrator_receipt_v4.py",
        "src/adamantine/v1/integrations/shield_orchestrator_receipt_v4_verifier.py",
        "src/adamantine/v1/policy/final_policy_engine.py",
        "tests/contracts/test_shield_orchestrator_receipt_v4_contract.py",
        "tests/integrations/test_shield_orchestrator_receipt_v4_verifier.py",
        "tests/integrations/test_shield_v49_external_verification_contract.py",
        "tests/policy/test_final_policy_engine_shield_v4_required.py",
        "src/adamantine/v1/fixtures/shield_v4/external_verifier_contract_v1_kat.json",
    ]
    for path in required_paths:
        assert path in verifier_doc or path in test_matrix
        assert (ROOT / path).exists()


def test_shield_v4_docs_lock_v4_required_downgrade_rejection() -> None:
    combined = "\n".join(read(path) for path in DOCS)

    required_phrases = [
        "shield_v4_required=True",
        "v3 receipt",
        "downgrade",
        "policy.v1",
        "classical-ed25519",
        "ml-dsa",
        "fn-dsa",
    ]
    for phrase in required_phrases:
        assert phrase in combined


def test_shield_v4_docs_lock_external_contract_consumer_boundary() -> None:
    combined = "\n".join(read(path) for path in DOCS)

    required_phrases = [
        "V4.9-L independent external-contract consumer proof",
        "SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json",
        "external_verifier_contract_v1_kat.json",
        "308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f",
        "verifier-controlled TEST-ONLY trust input",
        "standard_profile` is authenticated in each signature entry",
        "not a trust-registry-entry field",
        "A wallet consumes only AdamantineOS final output",
        "final_approval=false",
    ]
    for phrase in required_phrases:
        assert phrase in combined
