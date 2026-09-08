# AdamantineOS Shield v4 Final Verifier Proof Pack

Author attribution: DarekDGB
Status: V4.10-F candidate proof pack; post-commit gates pending
Repository: DigiByte-AdamantineOS

## 1. Scope and independent version decision

This pack indexes the implemented Shield v4 verifier, durable audit wrapper,
work budget, and final-policy gate. It is not a release or tag authorization.
The distribution `adamantine-wallet-os` deliberately remains `3.0.0` in F.
F changes documentation and tests only; it changes no runtime API or behavior.
No active runtime `__version__` or server-version field exists to update.
The next AdamantineOS release number is not assigned by this proof-only step;
any future stamp requires its independent release decision and alignment.
AdamantineOS does not inherit the six Shield repositories' `v4.0.0` tag.

The historical v3.0.0 proof set (925 tests, 4097 statements) is retained as
history, not relabeled as Shield v4 evidence. The old Full Integration Build
Ledger is unchanged. Current status is recorded in
[the Shield v4 release-status record](../ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md).

Source baseline: `6a17a5b3a21dfc833a2683cdc00acbd6ff1309ab`.
Source ZIP SHA-256:
`9ce4a79b18400e692cc90627879de6b67311ac58e5a83f6d42c8cbcdd3927433`.
Source Git tree: `092fd9e834613e043649b296cd089f4e78fc51e4`.
These identify the input, not a future F commit.

## 2. Authority and integration boundary

Shield v4 produces cryptographically verifiable decision evidence only.
AdamantineOS remains the final execution boundary. A wallet consumes only
AdamantineOS final output, never a raw receipt, component summary,
`handoff_allowed`, or the fixture's expected result as final approval.
Verified Shield evidence retains `final_approval=false`.

The final engine validates expected context and mode shape, then evaluates
`shield`, `wsqk_v2`, `qid`, `adaptive_core`, `ai_gateway`, `replay`,
`wallet_policy`, and `human`, in that order, before the final decision.
Evidence ALLOW does not override a failing local gate.

`shield_v4_required=True` explicitly requires verified v4 evidence.
The compatibility default remains `shield_v4_required=False`; F does not
enable v4-required mode automatically in the existing v2 runtime host.
The direct verifier/final-engine proofs are not proof of a deployed wallet
integration or a completed SDK. Existing v1/v2 execution callbacks remain
final-policy gated; this pack adds no signer, broadcaster, or execution API.
It changes no DigiByte consensus rule.

## 3. Shared KAT and frozen identities

The shared external KAT is
`src/adamantine/v1/fixtures/shield_v4/external_verifier_contract_v1_kat.json`.
Its exact file SHA-256 is
`308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f`.
The complete expected result is compared, not only an ALLOW flag.
All five component bundles and the Orchestrator bundle are independently
verified using verifier-controlled trust; embedded summaries are cross-checked.
The upstream self-excluding external-package manifest belongs to Orchestrator,
not the historical AdamantineOS foundation contract manifest.

| Identity | Frozen value |
| --- | --- |
| Receipt / verdict schema | `shield.receipt.v2` / `shield.verdict.v2` |
| Contract / canonicalization | `4` / `shield-v4-canon.v1` |
| Policy | `policy.v1` |
| Required ordered algorithms | `classical-ed25519`, then `ml-dsa` |
| Optional last algorithm | `fn-dsa` |
| ML-DSA profile | `fips204-ml-dsa-65-v1` |
| FN-DSA profile | `fips206-draft-falcon1024-v1` |
| Components | `adn`, `dqsn`, `guardian_wallet`, `qwg`, `sentinel_ai` |

ML-DSA, formerly CRYSTALS-Dilithium, and FN-DSA, based on Falcon, are separate
algorithms. Both required paths must pass. Optional FN-DSA may be absent;
when present it must verify, cannot rescue either required failure, and cannot
be reordered or normalized into compliance. Draft Falcon-1024 is not a final
FIPS 206 claim. File hashes and signed payload hashes are different identities.

## 4. Proof-to-test map

All paths below are repository-relative. Existing tests remain part of the
required full suite; F does not replace their negative matrices with prose.

| Requirement | Executable evidence |
| --- | --- |
| Complete shared KAT, all components/receipt, final evidence result | `tests/integrations/test_shield_v49_external_verification_contract.py` |
| Context, freshness, replay, registry floor, revocation, denylist, verifier-controlled trust | `tests/integrations/test_shield_orchestrator_receipt_v4_verifier.py`; `tests/integrations/test_shield_v49_external_verification_contract.py` |
| Required policy, v3 downgrade, authority fields, raw contract | `tests/contracts/test_shield_orchestrator_receipt_v4_contract.py`; `tests/policy/test_final_policy_engine_shield_v4_required.py` |
| FN-DSA absent/present, no rescue, profile binding, canonical order | `tests/integrations/test_shield_v48h_fn_dsa_optional_evidence.py`; `tests/integrations/test_shield_v48h_fn_dsa_signed_message_kat.py` |
| Multi-component fixture harness and negatives | `tests/integrations/test_shield_v4_full_multi_repo_integration_harness.py`; `tests/integrations/test_shield_v4_full_multi_repo_negative_matrix.py` |
| Privacy-safe observability and exact durable acknowledgement | `tests/integrations/test_shield_v410b_verification_audit.py` |
| Bounded snapshot, registry/replay work, preflight, global callback waves | `tests/integrations/test_shield_v410c_performance_dos_envelope.py` |
| Final policy order and local veto after valid Shield evidence | `tests/policy/test_final_policy_engine.py`; `tests/integrations/test_shield_v49_external_verification_contract.py` |
| Existing v1/v2 executor remains final-policy gated | `tests/test_milestone_18_authorized_red_team_review.py` |
| Verify-only real adapter and provider failures | `tests/integrations/test_shield_v4_real_crypto_backend_contract.py`; `tests/integrations/test_shield_v48h_e_oqs_falcon_backend.py` |
| F shared KAT through audited verification and final engine, ACK failure, source/doc/workflow locks | `tests/test_v410f_final_verifier_proof_pack.py` |

## 5. Audit and bounded-work contract

Release integrations requiring durable audit use
`verify_shield_v4_orchestrator_receipt_with_audit`. The unchanged ordinary
verifier does not itself require an audit sink. The wrapper returns only
after an exact atomic durable acknowledgement; it never updates replay state.
The sink's real durability and replay-store atomicity are deployment duties.
The in-memory test sink proves acknowledgement handling, not disk durability.

Audit output is the bounded `shield.verification_audit.v1` tagged union.
Raw request/key identifiers are hashed; raw receipts, signatures, keys,
nonces, personal data, and exception text are excluded. Limits are 24 records,
2048 bytes per record, and 49152 bytes per batch envelope.

The already parsed receipt is isolated by a bounded exact-JSON snapshot.
All six bundles and keys pass cheap preflight before canonical/hash work and
callbacks. Required-only work is 12 callbacks / 6 PQC; full optional evidence
is 18 callbacks / 12 PQC. Global waves are classical, ML-DSA, then FN-DSA.
The transport parser must separately enforce raw-message limits.

Normative contracts:
[audit v1](../CONTRACTS/shield_v4_verification_audit_v1.md) and
[performance/DoS v1](../CONTRACTS/shield_v4_performance_dos_envelope_v1.md).

## 6. Distinct validation gates

Standard CI runs the full suite with `--cov=adamantine` and
`--cov-fail-under=100`. Ordinary runs skip three gated native modules when
their enable flags are absent. Statement coverage is not branch coverage and
does not prove absence of all defects.

The native workflow must set both `SHIELD_V4_REAL_OQS=1` and
`SHIELD_V4_REAL_OQS_FALCON=1`. The exact six native nodes and guard invocation
are recorded in the [real-backend contract](../ADAMANTINEOS_SHIELD_V4_REAL_CRYPTO_BACKEND.md).
Require `tests=6 skipped=0 failures=0 errors=0 required=6` on the final F commit.
The proofs use live ML-DSA-65 and Falcon-1024 but TEST-ONLY classical callbacks.
The embedded-Falcon tamper negative is a receipt-integrity rejection before
native verification, not a native Falcon cryptographic-rejection measurement.
No production Ed25519 provider, key custody, HSM, FIPS-validated deployment,
side-channel resistance, or fully native three-algorithm deployment is proven.

The performance workflow separately pins Python 3.11.15 and its software and
environment. Its 20 warmups / 200 samples bound valid p95 at 50 ms and oversize
rejection p95 at 20 ms with deterministic callbacks. It measures Python
verification/audit overhead, not native PQC latency or universal hardware speed.
The native workflow still uses floating upstream dependencies; this pack does
not claim byte-reproducible native builds or change that workflow.

## 7. Completion and handoff

F preparation results and exact package/roadmap hashes belong in the controlled
roadmap handoff. Candidate commit-specific CI is not fabricated into this pack.
After the full copy set is committed, require standard CI, the exact six-node
native workflow, and the pinned performance workflow on that same commit.
Then inspect a fresh post-F ZIP against the delivered candidate.

F remains incomplete until those post-commit gates pass. Later V4.10 release
gates and DarekDGB's explicit tag approval remain separate.
