from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_milestone_17_public_name_and_package_boundary_are_locked() -> None:
    readme = read("README.md")
    security = read("SECURITY.md")
    changelog = read("CHANGELOG.md")
    pyproject = read("pyproject.toml")

    assert "# DigiByte AdamantineOS" in readme
    assert "DigiByte AdamantineOS is a **deterministic security decision engine" in readme
    assert "Security in AdamantineOS is based on" in security
    assert "Milestone 17: Rebrand, Proof Pack, and Docs Alignment" in changelog
    assert 'description = "DigiByte AdamantineOS deterministic security boundary"' in pyproject

    # Package/import names stay stable after Milestone 17; Milestone 19 stamps the release version.
    assert 'name = "adamantine-wallet-os"' in pyproject
    assert 'version = "3.0.0"' in pyproject


def test_milestone_17_proof_pack_maps_completed_level4_milestones() -> None:
    proof_pack = read("docs/PROOF_PACKS/ADAMANTINEOS_LEVEL4_INTEGRATION_PROOF_PACK.md")
    milestone_doc = read("docs/ADAMANTINEOS_MILESTONE_17_REBRAND_PROOF_PACK_AND_DOCS_ALIGNMENT.md")
    ledger = read("docs/ADAMANTINEOS_FULL_INTEGRATION_BUILD_LEDGER.md")

    for milestone in ("16B", "16C", "16D", "16E", "16F", "16G"):
        assert milestone in proof_pack

    required_paths = [
        "tests/integrations/test_milestone_16b_shield_orchestrator_v3_2_contract_harness.py",
        "tests/integrations/test_milestone_16c_shield_component_baseline_through_orchestrator.py",
        "tests/integrations/test_milestone_16d_q_id_external_baseline_compatibility.py",
        "tests/integrations/test_milestone_16e_adaptive_core_external_baseline_compatibility.py",
        "tests/integrations/test_milestone_16f_ai_gateway_external_baseline_compatibility.py",
        "tests/integrations/test_milestone_16g_full_level4_negative_matrix.py",
    ]
    for path in required_paths:
        assert path in proof_pack
        assert (ROOT / path).exists()

    assert "DigiByte AdamantineOS" in milestone_doc
    assert "no AdamantineOS tag yet" in milestone_doc
    assert "| 17 | Rebrand, proof pack, and docs alignment |" in ledger
    assert "Milestone 19 Release Stamp - v3.0.0" in ledger


def test_milestone_17_repository_identity_uses_new_github_slug() -> None:
    checked_paths = [
        "README.md",
        ".github/ISSUE_TEMPLATE/config.yml",
        "docs/ADAMANTINEOS_FULL_INTEGRATION_BUILD_LEDGER.md",
        "docs/ADAMANTINEOS_MILESTONE_17_REBRAND_PROOF_PACK_AND_DOCS_ALIGNMENT.md",
        "docs/PROOF_PACKS/ADAMANTINEOS_LEVEL4_INTEGRATION_PROOF_PACK.md",
    ]
    for path in checked_paths:
        content = read(path)
        assert "DigiByte-AdamantineOS" in content
        assert "DigiByte-Adamantine-Wallet-OS" not in content

    pyproject = read("pyproject.toml")
    assert 'name = "adamantine-wallet-os"' in pyproject
    assert 'version = "3.0.0"' in pyproject
