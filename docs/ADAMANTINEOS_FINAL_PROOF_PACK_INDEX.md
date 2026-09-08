# DigiByte AdamantineOS Final Proof Pack Index

Author attribution: **DarekDGB**
Repository: `DigiByte-AdamantineOS`
Public project name: **DigiByte AdamantineOS**
Current package version: `v3.0.0`
Current candidate: **Unreleased Shield v4 verifier; V4.10-F proof-only**
Tag status: **No new tag or retagging authorized by this index**
Historical milestone: **19 v3.0.0 release gate**

---

## 1. Purpose

This index separates current Shield v4 candidate evidence from the historical
Milestone 19 `v3.0.0` release-gate evidence set.

F deliberately keeps package 3.0.0 without choosing a new release number.
AdamantineOS does not inherit the six Shield repositories' v4.0.0 tag.
Historical release documents and the old build ledger remain unchanged.

### Current Shield v4 candidate evidence

- [Final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
- [Independent version and release status](ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md)
- [Verifier contract](ADAMANTINEOS_SHIELD_V4_PQC_VERIFIER.md)
- [Threat model](ADAMANTINEOS_SHIELD_V4_THREAT_MODEL.md)
- [Test matrix](ADAMANTINEOS_SHIELD_V4_TEST_MATRIX.md)
- [Real-backend proof](ADAMANTINEOS_SHIELD_V4_REAL_CRYPTO_BACKEND.md)
- [Verification audit](CONTRACTS/shield_v4_verification_audit_v1.md)
- [Performance/DoS envelope](CONTRACTS/shield_v4_performance_dos_envelope_v1.md)

The current candidate requires full standard CI and 100% coverage, the exact
six-node native guard with zero skips/errors/failures, the pinned performance
job, and a fresh post-F ZIP on the complete candidate commit. Preparation
results are recorded separately in the controlled roadmap handoff.

---

## 2. Historical v3.0.0 primary evidence set

| Evidence area | Repository artifact |
| --- | --- |
| Full integration ledger | `docs/ADAMANTINEOS_FULL_INTEGRATION_BUILD_LEDGER.md` |
| Milestone 16 scope lock | `docs/ADAMANTINEOS_MILESTONE_16_LEVEL4_MULTI_REPO_SCOPE_LOCK.md` |
| Milestone 16B receipt harness | `docs/ADAMANTINEOS_MILESTONE_16B_SHIELD_ORCHESTRATOR_RECEIPT_CONTRACT_HARNESS.md` |
| Milestone 16C Shield baseline through orchestrator | `docs/ADAMANTINEOS_MILESTONE_16C_SHIELD_COMPONENT_BASELINE_THROUGH_ORCHESTRATOR.md` |
| Milestone 16D Q-ID external baseline | `docs/ADAMANTINEOS_MILESTONE_16D_Q_ID_EXTERNAL_BASELINE_COMPATIBILITY.md` |
| Milestone 16E Adaptive Core external baseline | `docs/ADAMANTINEOS_MILESTONE_16E_ADAPTIVE_CORE_EXTERNAL_BASELINE_COMPATIBILITY.md` |
| Milestone 16F AI Gateway external baseline | `docs/ADAMANTINEOS_MILESTONE_16F_AI_GATEWAY_EXTERNAL_BASELINE_COMPATIBILITY.md` |
| Milestone 16G full negative matrix | `docs/ADAMANTINEOS_MILESTONE_16G_FULL_LEVEL4_NEGATIVE_TEST_MATRIX.md` |
| Milestone 17 rebrand/proof/docs alignment | `docs/ADAMANTINEOS_MILESTONE_17_REBRAND_PROOF_PACK_AND_DOCS_ALIGNMENT.md` |
| Milestone 18 authorized findings | `docs/ADAMANTINEOS_MILESTONE_18_AUTHORIZED_RED_TEAM_FINDINGS.md` |
| Milestone 18 final closure report archive | `docs/RED_TEAM/ADAMANTINEOS_MILESTONE_18_FINAL_CLOSURE_REVIEW.docx` |
| Milestone 18 final closure report Markdown | `docs/RED_TEAM/ADAMANTINEOS_MILESTONE_18_FINAL_CLOSURE_REVIEW.md` |
| Milestone 19 final release gate | `docs/ADAMANTINEOS_MILESTONE_19_FINAL_RELEASE_GATE.md` |
| Milestone 19 tag decision | `docs/ADAMANTINEOS_MILESTONE_19_TAG_DECISION.md` |
| v3.0.0 release notes | `docs/ADAMANTINEOS_V3_0_0_RELEASE_NOTES.md` |

---

## 3. Historical runtime authority evidence

Milestone 19 relies on the following runtime authority evidence being present and regression-locked:

```text
- final policy engine is on the live runtime path
- legacy v1 executor path is final-policy gated
- Q-ID reject reaches final policy engine and denies
- Shield reject reaches final policy engine and denies
- WSQK reject reaches final policy engine and denies
- wallet_policy / EQC reject reaches final policy engine and denies
- replay / nonce reject reaches final policy engine and denies
- human gate reject reaches final policy engine and denies
- executor runs only after ALLOW_FINAL_ADAMANTINEOS_DECISION
- reject branch unexpected engine ALLOW fails closed
```

---

## 4. Historical test evidence

Recorded Milestone 19 evidence before the historical release-stamp copy-back:

```text
PYTHONPATH=src python -m pytest -q
925 passed
100.00% coverage
TOTAL 4097 statements, 0 missed
```

This historical proof is not the current Shield v4 test count or coverage scope.

---

## 5. Historical release gate evidence rule

The historical v3.0.0 proof pack recorded these conditions:

```text
[x] Milestone 19 docs are copied back
[x] Fresh post-copy ZIP is inspected
[x] Tests pass again
[x] Coverage remains 100.00%
[x] Ledger and release gate agree
[x] Tag decision document remains explicit
[x] Maintainer explicitly approves tag creation after final copied-repo verification
```

Those historical approvals do not authorize any new release, creation of a
v4.0.0 AdamantineOS tag, or movement of an existing tag. Current Shield v4
candidate status is controlled by the release-status record above.
