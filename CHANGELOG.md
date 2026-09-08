# AdamantineOS - Changelog

License: MIT License
Author: DarekDGB
Repository: DigiByte AdamantineOS
Scope: Foundation Releases and Contract History

## Unreleased - V4.10-F Shield v4 final verifier proof pack

Author attribution: DarekDGB

- Consolidated the shared external KAT, independent signature verification,
  strict policy and optional FN-DSA behavior, trust/replay/context negatives,
  canonical order, durable audit, and bounded-work proof references.
- Added the final verifier proof pack, independent release-status record, and
  executable proof/documentation locks. The new composed test routes the exact
  shared KAT through audited verification and the final policy engine.
- Aligned active README, security guidance, verifier/threat/test/backend docs,
  and proof/documentation indexes while preserving historical v3 evidence.
- Deliberate no-bump: package remains 3.0.0. F changes no runtime, workflow,
  dependency, fixture, schema, or protocol identity. The next independent
  AdamantineOS release version is not assigned by F; no tag is authorized.
- Kept the existing compatibility default shield_v4_required=False explicit;
  no automatic v4 runtime-host enablement or deployed wallet/SDK claim.
- Made the copy set ASCII-safe and aligned the existing README-title assertion
  with its plain-text heading. All security and version assertions remain.

The current candidate is not the historical v3.0.0 tag. That historical record
below retains its original test counts and milestone decisions; those old
approvals do not authorize a new tag or retagging current main.

------------------------------------------------------------------------

## v3.0.0 - Final Policy Runtime Authority Release

**Status:** Historical v3.0.0 release record; not a current tag authorization
**Type:** Major release boundary, final-policy runtime authority, Shield integration closure, and evidence lock
**Compatibility:** No package distribution rename and no Python import-path change

DigiByte AdamantineOS `v3.0.0` is the first major release boundary after approximately seven months of design, integration, documentation, proof-pack building, fail-closed hardening, and authorized AI red-team review.

This release marks the point where AdamantineOS is no longer only a locked WSQK v2 / integration-preparation boundary. It now records the completed connection of the major protection layers into one deterministic final-policy authority path.

The headline of this release is the connected evidence architecture. Claude AI is recorded as authorized red-team evidence only; it is not the system story and it is not final authority.

### Connected system layers

`v3.0.0` aligns the public release record with the full connected architecture:

1. **Shield components**
   - Guardian Wallet
   - ADN
   - Sentinel AI
   - DQSN
   - QWG
   - Shield Orchestrator

2. **Evidence and policy layers**
   - Shield Orchestrator v3.2 receipt
   - WSQK v2 posture and policy evidence
   - Q-ID identity and session evidence
   - Adaptive Core advisory policy evidence
   - AI Gateway evidence-only path with no final authority
   - EQC / wallet-policy evidence
   - Replay / nonce freshness gate
   - Human review exact-context gate

3. **Final authority**
   - AdamantineOS final fail-closed decision engine
   - `FINAL ALLOW`
   - `FINAL DENY`
   - `HUMAN REVIEW REQUIRED`

### Release proof

```text
PYTHONPATH=src python -m pytest -q
925 passed
100.00% coverage
TOTAL 4097 statements, 0 missed
```

### What v3.0.0 locks

1. **Final-policy runtime authority**
   - The live runtime path invokes the final AdamantineOS policy engine before executor execution.
   - Executor execution is allowed only after `ALLOW_FINAL_ADAMANTINEOS_DECISION`.
   - Hard DENY dominates human review and all lower-priority review outcomes.

2. **Layer-connected evidence routing**
   - Q-ID rejects reach the final policy engine and stop at the Q-ID gate.
   - Shield rejects reach the final policy engine and stop at the Shield gate.
   - WSQK v2 rejects reach the final policy engine and stop at the WSQK gate.
   - Adaptive/Core wallet-policy and EQC rejects reach the final policy engine and stop at the wallet-policy gate.
   - Replay/nonce rejects reach the final policy engine and stop at the replay gate.
   - Human-gate rejects reach the final policy engine and stop at the human gate.

3. **Shield v3.2.0 integration boundary**
   - Shield component evidence is accepted only through the Shield Orchestrator receipt boundary.
   - Raw component bypasses remain rejected fail-closed.
   - Unknown or drifted registry/component evidence remains fail-closed.

4. **Legacy executor hardening**
   - The legacy `orchestrate_execution_v1` path is gated through the final policy engine before execution.
   - v1 remains compatible but cannot bypass final AdamantineOS authority.

5. **No-debt authorized red-team closure**
   - Claude AI red-team findings F1-F8 were accepted where valid and fixed.
   - Second-review N1/N2 were fixed.
   - Residual N7/N8 were closed/fixed instead of carried as debt.
   - Final closure report records PASS with no HIGH / MEDIUM / LOW / NOTE findings left open.

6. **Release-gate evidence lock**
   - Milestone 17 public rebrand and proof-pack alignment is complete.
   - Milestone 18 runtime authority wiring and red-team closure is complete.
   - Milestone 19 final release gate, tag decision, proof-pack index, README, changelog, docs index, and ledger are aligned for `v3.0.0`.

### Boundaries preserved

```text
Public project name: DigiByte AdamantineOS
Repository: DigiByte-AdamantineOS
Internal package distribution name: adamantine-wallet-os
Python import paths: unchanged
DigiByte consensus change: no
Wallet UI/key custody/transaction broadcasting: out of scope
```

### Tag decision

```text
Candidate tag: v3.0.0
Tag decision: APPROVED after release-stamp copy-back, CI green, and final fresh-ZIP inspection
Package version: 3.0.0
```

------------------------------------------------------------------------

## Unreleased - Milestone 18: Authorized Red-Team Review, Runtime Authority Wiring, and Fail-Closed Hardening

**Status:** Complete - fourth red-team passed; N8/N7 no-debt closure verified
**Type:** Runtime authority wiring, red-team fixes, and fail-closed hardening
**Compatibility:** No package rename, no import-path change, no version bump, and no AdamantineOS tag

Milestone 18 accepts and fixes the validated Claude AI red-team findings F1-F8, second-review findings N1/N2, third-review residual N1/N7/N8 notes, and closes with no known red-team technical debt carried forward.

Hardening added in the Milestone 18 hardening:

1. The live runtime path now invokes the final AdamantineOS policy engine before executor execution.
2. Cross-evidence context binding is enforced at the final policy engine when an expected context hash is supplied.
3. Truthy upstream `final_approval` attempts fail closed as authority bypass.
4. Hard DENY dominates human-review signals.
5. Hidden-authority scanning covers mapping, list, tuple, set, `__dict__`, and `__slots__` evidence.
6. Human-review detection requires exact status equality rather than substring matching.
7. Unknown evidence-supplied reason IDs are sanitized to `UNKNOWN_EXTERNAL_REASON` at the engine/runtime boundary.

Verification before maintainer copy-back:

```text
PYTHONPATH=src python -m pytest -q
925 passed
100.00% coverage
```


Additional no-debt closure hardening after Claude's fourth review:

8. N8 fixed: reject branches now fail closed if the final policy engine unexpectedly returns ALLOW inside an already-rejected runtime branch.
9. N7 closed: EQC aggregate runtime policy verdicts are explicitly documented as flowing through the stable `wallet_policy` local gate.

Milestone 18 is complete after fresh ZIP inspection and CI verification. AdamantineOS remains v2.2.0 and untagged; Milestone 19 remains pending as the final release gate.


Final external closure report archived:

```text
docs/RED_TEAM/ADAMANTINEOS_MILESTONE_18_FINAL_CLOSURE_REVIEW.docx
```

Claude AI final closure verdict: `PASS - Milestone 18 can be closed`. No known red-team note is carried forward as technical debt. This does not authorize release or tagging; Milestone 19 remains the final release gate.

------------------------------------------------------------------------

## Milestone 17: Rebrand, Proof Pack, and Docs Alignment

**Status:** Complete
**Type:** Documentation, release evidence, and public identity alignment
**Compatibility:** No package rename, no import-path change, no version bump, and no AdamantineOS tag

Milestone 17 performs a controlled public identity alignment from **DigiByte Adamantine Wallet OS** to **DigiByte AdamantineOS** and adds the Level 4 integration proof-pack structure before authorized red-team review.

Locked rules:

1. `DigiByte AdamantineOS` is the public project name going forward.
2. `AdamantineOS` is the short project name going forward.
3. Package names, import paths, repository path assumptions, and release version remain unchanged.
4. AdamantineOS remains `v2.2.0` and untagged until Milestones 17, 18, and 19 are complete and verified.
5. Milestone 17 does not create new authority paths or weaken any fail-closed boundary.

------------------------------------------------------------------------

## Unreleased - Milestone 18 second red-team hardening pass

- Fixed second-review N1 by replacing unconditional synthetic runtime evidence on the v2 final-policy path with evidence normalized only after real runtime boundaries accept Shield, Q-ID, Adaptive Core oracle, WSQK authority, EQC, and TVA/replay checks.
- Fixed second-review N2 by routing the legacy v1 executor path through final policy engine gating before executor execution.
- Updated runtime adapter guidance so integrators do not route live execution around the final policy engine.
- Added regression tests proving a live EQC deny reaches the final policy engine and that v1 execution is blocked when final policy denies.
- AdamantineOS remained v2.2.0 and untagged; this pass was superseded by fourth-review Option 2 closure.

## v2.2.0 - WSQK v2 Quantum-Aware Upgrade

**Status:** Locked
**Type:** Quantum-aware authority upgrade
**Compatibility:** Additive - legacy/v1 paths remain compatible unless WSQK v2 is explicitly required

This release upgrades WSQK inside AdamantineOS into a quantum-aware authority layer. WSQK v2 is now contract-defined, deterministically issued, reason-ID mapped, Truth Vector Authority (TVA) enforced, Q-ID posture bound, orchestrator propagated, and regression locked.

### What's locked:

1. WSQK v2 Authority Contract
   - `WSQKAuthorityV2` and `WSQKIssueRequestV2` defined
   - Required evidence families locked as a sorted canonical unique set
   - Deterministic `proof_bindings_hash` semantics sealed

2. Quantum-Aware Issuance and Reason IDs
   - Deterministic WSQK v2 issuer added
   - Stable reason IDs locked for malformed posture, invalid evidence families, unknown families, and binding failures
   - Fail-closed validation preserved

3. Truth Vector Authority (TVA) Enforcement
   - TVA enforces WSQK v2 posture requirements
   - Tampered proof binding hashes are denied before nonce use
   - WSQK v1 cannot satisfy explicit WSQK v2 requirements

4. Q-ID Hybrid Posture Binding
   - Hybrid-required posture requires classical AND PQC Q-ID posture
   - PQC-required posture requires PQC evidence
   - Posture mismatches deterministically deny

5. Orchestrator / Runtime Boundary Propagation
   - WSQK v2 requirements propagate through the runtime boundary
   - No silent v1 fallback when v2 is required
   - Downgrade attempts are regression locked

6. Tamperproof Regression Locks and Proof Pack
   - Negative-first tests cover hash tampering, context tampering, family drift, downgrade attempts, and Q-ID posture tamper
   - WSQK v2 proof pack maps contract -> invariants -> implementation -> tests -> CI proof
   - 100% coverage gate remains enforced

Rule: Any semantic change to WSQK v2 authority, proof binding, Q-ID posture binding, or TVA/orchestrator enforcement requires a new versioned compatibility lock.

------------------------------------------------------------------------

## v2.1.0 - AC v3 Governance Compatibility Lock

**Status:** Locked
**Type:** Compatibility lock (Adaptive Core v3 governance path sealed)
**Compatibility:** Additive - no production behavior changes

This release locks AdamantineOS compatibility with Adaptive Core v3 `upgrade_proposal_v3` artifacts and seals the first cross-repository governance evaluation path.

### What's locked:

1. Adaptive Core v3 Governance Compatibility
   - Proven compatibility with Adaptive Core v3 `upgrade_proposal_v3` artifacts
   - Stable proposal ingestion and validation path
   - Deterministic evaluation of governance proposals

2. Cross-Repository Hash Invariant
   - Deterministic `proposal_hash` invariant enforced across repositories
   - Hash drift fails CI
   - Canonical compatibility vector frozen

3. Governance Receipt Path Frozen
   - Compatibility vectors frozen in CI (`approve` + receipt path)
   - First upgrade proposal review path sealed end-to-end
   - Stable review receipt artifact boundary

4. Boundary Guarantees Reinforced
   - No production behavior changes
   - Governance compatibility locked without expanding runtime trust
   - Strengthened boundary between proposal artifacts and execution behavior

Rule: Any semantic change to Adaptive Core v3 governance artifact handling requires a new versioned compatibility lock.

------------------------------------------------------------------------

## v2.0.1 - Sealed Foundation (100% CI Enforcement)

**Status:** Locked
**Type:** Integrity lock (coverage enforcement hardening)
**Compatibility:** No functional or protocol changes

This release seals the AdamantineOS v2.0.x foundation by enforcing a strict 100% coverage regression gate in CI.

### What's locked:

1. Coverage Policy Hardened
   - `--cov-fail-under` raised from 95% to 100%
   - CI fails on any uncovered execution path
   - No tolerance margin

2. Runtime Surface Included
   - All runtime layers included in coverage scope
   - No coverage omit rules
   - No hidden escape paths

3. Regression Integrity Reinforced
   - 493 tests passing
   - Deterministic execution fully exercised
   - Fail-closed paths fully covered

Rule: Any uncovered execution path will fail CI.

------------------------------------------------------------------------

## v2.0.0 - Runtime Host v2 + Execution Boundary Seal

**Status:** Locked
**Type:** Major release (runtime host + execution_response_v2 seal)
**Compatibility:** Breaking - execution response upgraded to v2 contract

This release seals the mobile runtime host (v2) and locks deterministic execution behavior end-to-end.

### What's locked:

1. Runtime Host v2
   - `run_mobile_execution_call_v2` as authoritative execution entrypoint
   - Deterministic policy injection
   - Strict nonce store enforcement
   - Stable executor interaction boundary

2. Execution Response v2 (Contract Freeze)
   - `v: execution_response_v2`
   - Stable `decision` object structure
   - Stable `reason_id`
   - Stable `context_hash`
   - Locked `artifacts` shape
   - Deterministic `protection_mode`
   - Deterministic nonce semantics

3. Proof Pack v2_0_0_runtime
   - request_allow.json
   - request_deny.json
   - request_hostile_context_mismatch.json
   - response_allow.json
   - response_deny.json
   - response_hostile_context_mismatch.json
   - Canonical SHA256 manifest lock
   - Strict fixture-set exact-match enforcement

4. Determinism Enforcement
   - 50-run replay determinism tests (allow + hostile)
   - Stable canonical JSON dumps
   - CI fails on any payload drift

5. Fail-Closed Guarantees Reinforced
   - Adapter structural violations -> deterministic deny
   - Manifest drift -> CI failure
   - Canonical hash mismatch -> CI failure

Rule: Any change to execution_response_v2 shape requires a new major version.

------------------------------------------------------------------------

## v1.5.0 - Mobile Contract v2 + Conformance Freeze

**Status:** Locked
**Type:** Contract extension (mobile v2 freeze + deterministic conformance pack)
**Compatibility:** Additive - v1.4.x contracts remain valid unless mobile v2 is explicitly used

This release freezes the Mobile Integration Contract v2 and seals the OS Proof Pack for deterministic CI enforcement.

### What's locked:

1. Mobile Request Contract v2
   - Strict schema validation (unknown fields rejected)
   - Required `audit` field enforced
   - Deterministic request canonicalization
   - Explicit timebox + authority validation requirements

2. Mobile Response Contract v2
   - Stable response envelope
   - Deterministic `decision`, `reason_id`, `context_hash`
   - `protection_mode` semantics locked (legacy | minimal | full)
   - Strict response schema (no unknown fields allowed)

3. OS Proof Pack v1_5_0 (Mobile)
   - Golden roundtrip fixtures (legacy / minimal / full)
   - Canonical SHA256 manifest lock
   - Fixture set exact-match enforcement
   - Canonical JSON duplicate-key rejection

4. Determinism Enforcement
   - 100-run replay determinism tests
   - Stable ordering guarantees
   - Stable artifact shape enforcement
   - CI fails on any payload drift

5. Fail-Closed Guarantees Extended
   - Missing required request fields -> schema reject
   - Unknown request fields -> schema reject
   - Unknown response fields -> schema reject
   - Hash mismatch -> CI failure
   - Manifest drift -> CI failure

Rule: Any change to mobile request/response shape requires a major version bump.

------------------------------------------------------------------------

## v1.4.0 - Q-ID Linkage Hardened (Replay Proof Gate)

**Status:** Locked
**Type:** Contract hardening (Q-ID binding + replay-proof validation)
**Compatibility:** Additive - legacy/v1.3 proof packs remain valid unless policy enables the latch

This release locks:

- Q-ID replay proof contract (`QIDReplayProof`) and deterministic adapter validation
- Distinct reason IDs for missing/invalid replay proof and binding mismatches
- Policy latch `require_qid_replay_proof` (deny-by-default; opt-in hardening)
- OS Proof Pack v1_4_0 fixtures + manifest lock (allow + fail-closed deny cases)

------------------------------------------------------------------------

## v1.3.0 - Shield Interfaces Frozen + Posture Locked

**Status:** Locked
**Type:** Contract hardening (Shield v3 + posture + regression locks)
**Compatibility:** Additive only - response adds `protection_mode` and new strict fixtures

This release freezes the Shield v3 external evidence interface and locks deterministic, auditable posture outputs.

1. Shield v3 Strict Interface Freeze
2. Protection Mode Output (auditable)
3. No Silent Downgrade (policy posture latches)
4. Regression Locks

------------------------------------------------------------------------

## v1.2.0 - Integration Harness Sealed

**Status:** Locked
**Type:** Deterministic integration freeze (execution proof pack)
**Compatibility:** Additive only - contracts unchanged

This release seals the deterministic integration harness for AdamantineOS.

Seal Statement:

As of v1.2.0, the execution integration layer is cryptographically reproducible and CI-enforced.

------------------------------------------------------------------------

## v1.0.0 - Foundation Sealed

**Status:** Locked
**Type:** Foundation seal (contracts + deterministic reasoning + boundaries)
**Compatibility:** Additive changes only beyond this point

This release seals the AdamantineOS foundation.

Breaking changes require a new major version.


------------------------------------------------------------------------

## Unreleased - Milestone 18 Option 2 full evidence-level wiring pass

- Kept Milestone 18 open after Claude AI third confirmation found residual N1 scope.
- Selected Option 2 instead of accepting residual synthetic/aggregate-only evidence scope.
- Routed Q-ID, Q-ID replay, Adaptive Core oracle, Shield, WSQK, TVA/replay, human gate, and EQC denial classes into `evaluate_final_policy_engine` before executor execution.
- Added regression tests proving Q-ID, Shield, WSQK, replay, and human gate failures reach the final policy engine and do not execute.
- Preserved `v2.2.0`, package/import names, and untagged status.

Verification:

```text
PYTHONPATH=src python -m pytest -q
925 passed
100.00% coverage
```
