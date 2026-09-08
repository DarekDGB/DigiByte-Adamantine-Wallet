# AdamantineOS Documentation Index

## Current Version

**Package 3.0.0 retained; unreleased Shield v4 verifier candidate**

V4.10-F deliberately makes no version bump or tag decision. The next
independent AdamantineOS release number is not assigned here. Historical
v3.0.0 evidence is separate from the current verifier candidate.

## Current Shield v4 verifier proof

- [Final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
- [Independent release status](ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md)
- [Verifier contract](ADAMANTINEOS_SHIELD_V4_PQC_VERIFIER.md)
- [Threat model](ADAMANTINEOS_SHIELD_V4_THREAT_MODEL.md)
- [Test matrix](ADAMANTINEOS_SHIELD_V4_TEST_MATRIX.md)
- [Real crypto backend](ADAMANTINEOS_SHIELD_V4_REAL_CRYPTO_BACKEND.md)

------------------------------------------------------------------------


## Historical v3.0.0 Connected Evidence Architecture

The `v3.0.0` release connects Shield components, Shield Orchestrator v3.2 receipts, WSQK v2, Q-ID, Adaptive Core, AI Gateway evidence-only input, replay / nonce enforcement, wallet policy evidence, and human review into the final AdamantineOS fail-closed decision engine.

- Shield components: Guardian Wallet, ADN, Sentinel AI, DQSN, QWG
- Shield Orchestrator v3.2 receipt boundary
- Shield runtime boundary lock: production uses Orchestrator receipt-only by default; legacy bundle mode is explicit test-only compatibility
- WSQK v2 posture / policy evidence
- Q-ID identity / session evidence
- Adaptive Core advisory policy evidence
- AI Gateway evidence only, never final authority
- Replay / nonce freshness gate
- Human review exact-context gate
- Final allow / deny / review decision
- Deprecated v1 orchestrator is internal legacy compatibility only; production integrations use the v2 runtime host / orchestrator_v2 boundary

------------------------------------------------------------------------

# Core Documentation

Architecture and system design documents.

-   Adaptive Core Governance Flow
-   Contracts and artifact definitions
-   Invariant definitions

------------------------------------------------------------------------

# Governance

Documents describing governance interactions.

-   Adaptive Core -> Adamantine Governance Flow
-   Governance Review Contract

------------------------------------------------------------------------

# Contracts

Artifact schemas and interface definitions.

-   upgrade_proposal_v3
-   proposal_review_receipt_v1
-   wsqk_authority_v2
-   WSQK v2 reason IDs
-   WSQK v2 Q-ID posture binding
-   [AI Gateway policy-bound evidence V2](CONTRACTS/ai_gateway_policy_bound_evidence_v2.md)

------------------------------------------------------------------------

# Security Principles

AdamantineOS follows strict architectural guardrails:

-   deterministic behavior
-   fail-closed validation
-   canonical serialization
-   explicit invariants
-   no silent fallback

------------------------------------------------------------------------

# Proof Packs

Audit maps connecting contracts, invariants, implementation, tests, and CI proof.

-   [WSQK v2 Quantum-Aware Proof Pack](PROOF_PACKS/wsqk_v2_quantum_aware_proof_pack.md)
-   [Shield v4 Final Verifier Proof Pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)

------------------------------------------------------------------------

# Proof Philosophy

Every major feature is supported by:

-   deterministic tests
-   contract schemas
-   documentation alignment


------------------------------------------------------------------------

## Historical v3.0.0 Release Gate

Final release-gate and proof documents for the AdamantineOS v3.0.0 tag boundary.

-   [Milestone 19 Final Release Gate](ADAMANTINEOS_MILESTONE_19_FINAL_RELEASE_GATE.md)
-   [Milestone 19 Tag Decision](ADAMANTINEOS_MILESTONE_19_TAG_DECISION.md)
-   [Shield Runtime Boundary Lock](ADAMANTINEOS_SHIELD_RUNTIME_BOUNDARY_LOCK.md)
-   [Reproducible Audit Guide](ADAMANTINEOS_REPRODUCIBLE_AUDIT_GUIDE.md)
-   [Q-ID Canonical JSON Profile](ADAMANTINEOS_QID_CANONICAL_JSON_PROFILE.md)
-   [Final Proof Pack Index](ADAMANTINEOS_FINAL_PROOF_PACK_INDEX.md)
-   [v3.0.0 Release Notes](ADAMANTINEOS_V3_0_0_RELEASE_NOTES.md)

Milestone 19 records the historical v3.0.0 release boundary. Its old approval
text is not current Shield v4 evidence or permission to create or move a tag.
The current candidate's post-commit standard, six-node native, performance,
and fresh-ZIP gates are in the Shield v4 release-status record above.


## Step 8.6 Receipt Denylist Wiring

Shield receipt denylisting is wired through trusted `RiskPolicy.rejected_shield_receipt_hashes` only. Untrusted request payloads cannot supply or modify the denylist. Denylisted receipt hashes fail closed as stale/replay-risk Shield evidence before EQC continuation.
