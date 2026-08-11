# DigiByte AdamantineOS

## Milestone 18 - Final Red-Team Closure Review

*No-debt closure hardening for N7 / N8 - fifth and final pass*

| Target | DigiByte-AdamantineOS (v2.2.0, untagged) |
| --- | --- |
| Review type | Milestone 18 final closure red-team - source- and execution-verified |
| State at review | M17 complete; all M18 fix passes + N7/N8 closure hardening applied; 925 passed; 100% coverage |
| Prior result | Fourth review = PASS WITH NOTES, M18 can close; N1/N2 fixed; N7/N8 left as notes |
| This pass | Maintainer refused to carry N7/N8 as debt; closure hardening applied |
| Author attribution | DarekDGB |
| Reviewer | Independent review |
| Date | 2026-06-11 |
| Method | Read source AND executed the live orchestrator + engine + all 11 M18/N regression tests in-sandbox, including the N8 forced-divergence mutation and a real nonce replay. CI log (925/100%) reconciled to source. Full pytest not re-run (no network); pass count from CI log. |

VERDICT

> PASS - Milestone 18 can be closed
> N8 is FIXED and N7 is CLOSED, both verified by execution and locked by regression tests. N1 and N2 remain FIXED - the N8 reject-branch edits did not disturb the per-source wiring; every source (Q-ID, Shield, WSQK, oracle/EQC, real replay, human) still reaches the engine and is denied by it, with the executor never called on a reject path.
> I attacked N8 directly: forcing the engine to ALWAYS-ALLOW inside each reject branch still yields status=deny with artifacts.final_policy_invariant.status=fail_closed and executor not called. Control flow and engine verdict can no longer silently diverge - a divergence is coerced to an explicit DENY invariant violation in real code (not a strippable assert).
> No HIGH / MEDIUM / LOW / NOTE findings remain open. No red-team note is carried forward as debt. Milestone 18 can be closed, but AdamantineOS must remain untagged until Milestone 19. This review does not approve release or tagging.

## 1. Findings status - full history

| ID | Finding | Status | Basis |
| --- | --- | --- | --- |
| F1-F8 | First red-team | FIXED | Engine wiring, context binding, authority bypass, human-review, reason sanitization - all fixed in earlier passes; re-confirmed no regression this pass. |
| N1 | Synthetic always-ALLOW runtime evidence | FIXED | Every per-source failure reaches the engine and is denied by it. Re-verified live this pass (section 4). |
| N2 | Legacy v1 executor bypass | STILL FIXED | v1: enforce_tva -> engine -> execute only after ALLOW. Re-verified; adapter docs still forbid bypass. |
| N3-N6 | Doc/wiring notes from rounds 2-3 | CLOSED | Superseded by Option 2 wiring and corrected ledger wording in earlier passes; no residual. |
| N7 | EQC surfaced via wallet_policy gate label | CLOSED | Mapping now explicitly documented in BOTH findings doc and ledger, and regression-locked by a test asserting the exact wording. Honest closure, not a silent rename. |
| N8 | Reject-branch deny could diverge from engine verdict | FIXED | Reject branches now coerce an unexpected engine ALLOW to a DENY invariant violation and fail closed. Mutation-proven + regression-locked. |

## 2. N8 - reject-branch / engine divergence

Status: FIXED

The fix adds _reject_branch_invariant_result(), called inside _final_policy_denied_response_v2 before the response is built. If the engine state is ALLOW_FINAL_ADAMANTINEOS_DECISION inside a reject branch, it is coerced to DENY_GATE_SHAPE_INVALID with reason DENY_POLICY and dominant reason FINAL_POLICY_UNEXPECTED_ALLOW_ON_REJECT_BRANCH; the response records final_policy_invariant.status=fail_closed and the original_state.

### 2.1 Mutation proof (engine forced to ALWAYS-ALLOW)

```text

ENGINE-FORCED-ALLOW  QID_REJECT    -> deny  reason=DENY_POLICY  invariant=fail_closed  exec=False
ENGINE-FORCED-ALLOW  SHIELD_LAYERS -> deny  reason=DENY_POLICY  invariant=fail_closed  exec=False
ENGINE-FORCED-ALLOW  WSQK_REJECT   -> deny  reason=DENY_POLICY  invariant=fail_closed  exec=False

```

Even with the engine subverted to ALLOW, every reject branch denies and never executes. This is the exact divergence scenario N8 was raised for, and it now fails closed.

- The coercion is real control-flow code, not an assert - it cannot be stripped by python -O.

- executor.execute is never reached on any reject path, with or without the forced ALLOW.

- Regression-locked: test_milestone_18_n8_reject_branch_unexpected_engine_allow_fails_closed monkeypatches the engine to ALLOW on a real qid-reject payload and asserts deny + DENY_POLICY + final_policy_invariant.status=fail_closed + original_state=ALLOW + executor.called False. Passes live; would fail if the guard were removed.

## 3. N7 - EQC / wallet_policy audit mapping

Status: CLOSED

The maintainer kept the stable wallet_policy local-gate contract (avoiding a churny rename that would have rippled through gate ordering and tests) and instead made the meaning explicit. The exact sentence - "EQC aggregate runtime policy verdict is intentionally surfaced through the stable wallet_policy local gate" - now appears in both docs/ADAMANTINEOS_MILESTONE_18_AUTHORIZED_RED_TEAM_FINDINGS.md and docs/ADAMANTINEOS_FULL_INTEGRATION_BUILD_LEDGER.md (confirmed present in both).

A regression test (test_milestone_18_n7_eqc_wallet_policy_mapping_is_explicit_in_docs) asserts that wording is present in both files, so the documentation cannot silently rot. This is an honest "close with documented rationale," an acceptable resolution for an audit-clarity note - the mapping can no longer mislead an auditor without the explanation sitting right next to it.

Minor observation (not a finding): the regression lock is a substring match; if the canonical wording is ever reworded the test must be updated in lockstep. That is the intended behaviour (it forces a conscious edit) but worth noting for future maintainers.

## 4. N1 / N2 regression after the N8 edit

Because N8 changed the reject-branch response path, I re-ran the full per-source sweep to confirm nothing regressed:

```text

HAPPY      allow  engine=1  stop=final_adamantineos_decision  exec=True
QID        deny   engine=1  stop=qid            rej=[qid]      exec=False
SHIELD_LYR deny   engine=1  stop=shield         rej=[shield]   exec=False
WSQK       deny   engine=1  stop=wsqk_v2        rej=[wsqk_v2]  exec=False
ORACLE     deny   engine=1  stop=wallet_policy                 exec=False
HUMAN      deny   engine=1  stop=human                         exec=False
REPLAY#1   allow  engine=1  stop=final_adamantineos_decision  exec=True
REPLAY#2   deny   engine=1  stop=replay                        exec=False   (real nonce reuse)

```

- All six source classes + real replay still reach the engine and deny at the correct gate; executor never runs on a reject path. No regression.

- No synthetic always-ALLOW evidence hides in any live reject path - failing sources carry accepted_as_evidence=False at their own gate.

- N2 intact: orchestrate_execution_v1 still runs enforce_tva (non-executing) -> engine -> executor.execute only after ALLOW (lines 299/307/318/336). runtime_adapter docs still say "never route live execution around the final policy engine."

- All 11 Milestone 18 / N-series tests pass live (9 from rounds 1-4 plus the new N7 and N8 tests).

## 5. Core protections and fresh red-team (areas 5-8)

| Area | Result | Detail |
| --- | --- | --- |
| TVA / executor ordering | NO REGRESSION | v2 uses its own non-executing run_with_tva; boundary.run_with_tva not used in v2; executor only after engine ALLOW; broad except -> status=error, never allow. |
| DENY dominance / human review | NO REGRESSION | DENY dominates ALLOW and HUMAN_REVIEW; rejected+human-review token -> DENY_EVIDENCE_REJECTED; runtime maps non-ALLOW to deny; no autonomous allow. |
| Context binding | NO REGRESSION | Spliced context and missing context both -> DENY_CONTEXT_MISMATCH. |
| Reason ID integrity | NO REGRESSION | Unknown/empty/non-string/spoofed -> UNKNOWN_EXTERNAL_REASON. |
| Authority bypass | NO REGRESSION | Truthy final_approval (True/1/'yes'/object()/list/dict) and forbidden keys in dict/dataclass/slots/nested list/tuple/set -> DENY_AUTHORITY_BYPASS. |
| Docs / ledger truthfulness | HONEST | M17 complete; M18 = closure hardening pending this review; F1-F8 + N1-N8 recorded; N7/N8 not hidden; 'no technical debt carried forward' stated; repeated 'no AdamantineOS tag is created'; 'does not authorize tagging'; v2.2.0; M19 pending. |
| Fresh independent sweep | NOTHING NEW | No fail-open fallback, no v1/v2 inconsistency, no fixture-only security, no synthetic ALLOW in live paths, no mutable-shared-state or import-path weakness. Exceptions fail closed. |

No new HIGH / MEDIUM / LOW / NOTE finding.

## 6. CI / coverage reconciliation

CI log (925 passed, 100.00%, 4097 statements, 0 missed, Python 3.11.15) reconciles with source. Deltas match the N7/N8 closure work:

```text

orchestrator_v2.py   283 -> 291 stmts (+8)   # _reject_branch_invariant_result + guard wiring
final_policy_engine.py 160 stmts (unchanged) # no regression
orchestrator_v1.py   155 stmts (unchanged)   # N2 gating intact
TOTAL               4089 -> 4097 (+8)         # 923 -> 925 tests (+2: N7, N8)

```

The new N8 fail-closed branch is covered by its forced-divergence test rather than left as an uncovered 'cannot happen' line - the right choice, since the test also proves the guard works. Coverage gate (--cov-fail-under=100) holds. Pass count taken from the CI log; pytest not re-run here (no network).

## 7. Closure decision

N7: closed. N8: fixed. N1: fixed. N2: fixed. No findings of any severity remain open, and no note is carried forward as debt.

Milestone 18 can be closed, but AdamantineOS must remain untagged until Milestone 19.

Milestone 19 (final release gate) remains the correct and only place for the tag decision. Nothing in this review authorizes release or tagging.

Closing note across the five passes: the final policy engine progressed from absent at runtime (round 1), to present-but-decorative (round 2), to EQC-only (round 3), to adjudicating every source (round 4), to divergence-proof and debt-free (round 5). The no-shortcuts path produced a genuinely clean close.

## Appendix A - Reproduction (in-sandbox)

### A.1 N8 forced-divergence (engine made ALWAYS-ALLOW)

```text

QID_REJECT    -> deny  invariant=fail_closed  exec=False
SHIELD_LAYERS -> deny  invariant=fail_closed  exec=False
WSQK_REJECT   -> deny  invariant=fail_closed  exec=False

```

### A.2 N1 per-source sweep (post-N8 edit)

```text

QID->qid  SHIELD->shield  WSQK->wsqk_v2  ORACLE->wallet_policy  HUMAN->human  REPLAY->replay
all: engine=1, exec=False on reject; HAPPY + REPLAY#1: allow, exec=True

```

### A.3 N7 documentation lock

```text

grep -c "EQC aggregate runtime policy verdict ... stable wallet_policy local gate"
  findings doc: 2    ledger: 2     (present in both; test asserts presence)

```

### A.4 All M18/N tests + engine guards

```text

Milestone18/N tests: 11 passed, 0 failed
F2 splice/missing->DENY_CONTEXT_MISMATCH  F3 truthy->DENY_AUTHORITY_BYPASS
F4 rej+HR->DENY_EVIDENCE_REJECTED  F5 nested->DENY_AUTHORITY_BYPASS
F6 substring->not fooled  F7 unknown->UNKNOWN_EXTERNAL_REASON

```

End of final Milestone 18 closure review. Verified from source and in-sandbox execution, including the N8 forced-divergence mutation and a real nonce replay; full pytest suite not re-run in this environment (pass count from the provided CI log). Closure of Milestone 18 and all release/tag authority remain with the maintainer. This review does not approve release or tagging.
