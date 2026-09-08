# AdamantineOS Shield v4 PQC Verifier

Author attribution: DarekDGB
Status: Shield v4 V4.10-F final verifier candidate proof lock
Scope: AdamantineOS-side Shield v4 verifier and external-contract consumer boundary, not a Shield v4 release claim

## 1. Boundary statement

AdamantineOS remains the final execution boundary.

Shield v4 produces cryptographically verifiable decision evidence only. Shield v4 does not sign transactions, does not broadcast transactions, does not change DigiByte consensus, and does not grant final execution approval.

The AdamantineOS Shield v4 verifier accepts or rejects Shield v4 evidence before the final policy engine can continue. Even when Shield v4 evidence verifies, final approval can only be produced by the AdamantineOS final policy engine after all local gates have also passed.

## 2. Current implementation surface

The Shield v4 AdamantineOS boundary is currently split across these files:

- `src/adamantine/v1/contracts/shield_orchestrator_receipt_v4.py`
- `src/adamantine/v1/integrations/shield_orchestrator_receipt_v4_verifier.py`
- `src/adamantine/v1/policy/final_policy_engine.py`
- `src/adamantine/v1/fixtures/shield_v4/valid_allow_signed_receipt.json`
- `src/adamantine/v1/fixtures/shield_v4/deny_signed_receipt.json`
- `src/adamantine/v1/fixtures/shield_v4/tampered_signature_deny.json`
- `src/adamantine/v1/fixtures/shield_v4/v3_downgrade_rejected.json`
- `src/adamantine/v1/fixtures/shield_v4/full_multi_repo_v4_fn_dsa_allow_flow.json`
- `src/adamantine/v1/fixtures/shield_v4/fn_dsa_signed_message_draft_profile_kat.json`
- `src/adamantine/v1/fixtures/shield_v4/external_verifier_contract_v1_kat.json`

Fixture tests explicitly inject the TEST-ONLY deterministic signature verifier. The public verifier API has no default signature backend, and real backends remain verify-only. Production PQC backend wiring must preserve the same schema, canonicalization, domain separation, policy, trust-registry, standard-profile binding, and fail-closed behavior.

### 2.1 Independent external-contract consumer proof

AdamantineOS pins a byte-identical copy of the Orchestrator Shield v4 external-verifier fixture at:

- `src/adamantine/v1/fixtures/shield_v4/external_verifier_contract_v1_kat.json`

Its SHA-256 is `308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f`. The upstream package is defined by `docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json` in DGB-Quantum-Shield-Orchestrator. That self-excluding package manifest, not the older AdamantineOS foundation contract manifest, controls this V4.9 external contract.

The fixture contains verifier-controlled TEST-ONLY trust input. Its registry is never receipt authority. `standard_profile` is authenticated in each signature entry and checked against the verifier allow-list; it is not a trust-registry-entry field. AdamantineOS independently re-verifies the component and Orchestrator bundles rather than trusting the signed `component_signature_results` summary.

The positive result is accepted as evidence only and always retains `final_approval=false`. Replay, stale evidence, revoked keys, registry rollback, denylisted receipt hashes, wrong context, unsupported profiles, noncanonical bundle order, weakened policy, and receipt-supplied trust are rejected fail-closed.

A wallet consumes only AdamantineOS final output. It must never treat the raw Orchestrator receipt, the fixture's expected result, or upstream `handoff_allowed` evidence as final execution authority.

## 3. Required Shield v4 receipt contract

A Shield v4 receipt accepted by AdamantineOS must use:

- `schema_version = shield.receipt.v2`
- `contract_version = 4`
- `canonicalization_profile = shield-v4-canon.v1`
- `signature_policy = policy.v1`
- `key_registry_version` as a positive integer
- `receipt_hash` as lowercase SHA-256 hex
- `signed_payload_hash` as lowercase SHA-256 hex
- `signature_bundle.schema_version = shield.signature_bundle.v1`

A v3 receipt submitted while Shield v4 is required is a downgrade attempt and must be rejected fail-closed.

## 4. Algorithm policy

Policy `policy.v1` requires strict AND semantics for:

- `classical-ed25519`
- `ml-dsa`

`ml-dsa` means ML-DSA, formerly CRYSTALS-Dilithium.

`fn-dsa` means FN-DSA, based on Falcon. FN-DSA/Falcon is separate from ML-DSA and must never be described as ML-DSA.

`fn-dsa` is optional evidence only in the current policy. It must never override failure of a required signature path. AdamantineOS accepts absence of FN-DSA in this policy version, but if FN-DSA is present it must verify independently or the receipt is rejected fail-closed. The current locked FN-DSA profile is `fips206-draft-falcon1024-v1`, representing draft Falcon-1024 profile separation only; it is not a public final FIPS 206 claim.

The verifier must reject:

- missing required algorithm entries
- duplicate algorithm entries
- noncanonical algorithm order
- unknown algorithms
- unsupported algorithms
- a weaker embedded policy than the verifier-required policy
- signature bundles that behave as first-valid-wins instead of strict AND
- unsupported or flipped `standard_profile` values
- present-but-invalid optional FN-DSA evidence

### 4.1 Canonical signature-bundle order and preflight

Every raw Orchestrator receipt bundle and every embedded component bundle must use this exact sequence:

1. `classical-ed25519`
2. `ml-dsa`
3. optional `fn-dsa`, when present

AdamantineOS validates the received sequence and never sorts, repairs, or otherwise normalizes signature evidence into compliance. Reversed required order, optional-first order, and every optional interleaving are rejected fail-closed.

Before any trust-registry key lookup or cryptographic verifier call, AdamantineOS completes a receipt-wide preflight over every embedded component bundle and the top-level Orchestrator bundle. The preflight validates bundle and entry shape, supported algorithms and profiles, exact order, required presence, duplicate algorithms, duplicate key identities, signed payload hashes, domain tags, key identifiers, and key versions. The private bundle verifier repeats the same preflight before its own trust or cryptographic work, so direct internal use cannot bypass the boundary.

V4.9-J introduced outer entry snapshots. V4.10-C additionally isolates the whole
receipt through a bounded exact-JSON snapshot before canonicalization or
callbacks; arbitrary mappings, cycles, and over-limit input are rejected.
This is bounded JSON isolation, not general-purpose copying of arbitrary objects.

The strict required `classical-ed25519` plus `ml-dsa` AND policy is unchanged. The optional entry remains last and carries draft FN-DSA/Falcon-1024 evidence only. Optional-present-invalid remains fatal, and optional evidence cannot rescue either required path.

## 5. Domain separation and signed payload hashes

The AdamantineOS contract uses domain separation for Shield v4 signed payload hashes:

- `DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1`
- `DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1`

The domain tag is part of the signed payload hash material. A component verdict signature must not verify as an Orchestrator receipt signature, and an Orchestrator receipt signature must not verify as a component verdict signature.

## 6. Trust registry checks

The verifier trust registry must bind each signature to:

- role
- key id
- key version
- algorithm
- validity window
- active or revoked status
- key registry version

The signature contract and cryptographic signed-message construction bind the algorithm-specific standard profile separately from the trust-registry record.

A signature is rejected if:

- the key is missing from the trusted registry
- the key role does not match the artifact being verified
- the key id, version, algorithm, or supported standard profile does not match the verifier contract
- the key is revoked
- the key is outside its validity window
- the receipt or component verdict was produced outside the key validity window
- the registry version is below the caller-required minimum or disagrees with the receipt and component registry versions

## 7. Freshness and replay checks

Shield v4 evidence must carry signed freshness fields:

- `request_id`
- `freshness_nonce`
- `not_before`
- `not_after`

The verifier must reject stale, not-yet-valid, malformed, or replayed receipts. Replay rejection is not optional when Shield v4 evidence is used as an AdamantineOS input.

## 8. Component requirements

The verifier requires all five Shield components:

- `adn`
- `dqsn`
- `guardian_wallet`
- `qwg`
- `sentinel_ai`

Each component must have a verified signature summary and each component summary must satisfy the required `policy.v1` algorithms. If a component includes optional FN-DSA evidence, AdamantineOS independently verifies it and rejects any embedded summary that claims FN-DSA without a matching verified signature, or hides FN-DSA that was actually present and verified.

A valid Orchestrator receipt is not enough if component verification is missing, incomplete, unsigned, downgraded, or mismatched against the expected context hash.

## 9. No upstream final authority

Shield v4 evidence must not contain final execution authority. The contract and verifier reject authority-bypass fields, including but not limited to:

- `sign`
- `broadcast`
- `override`
- `final_approval`
- `force_allow`
- `auto_approve`
- `can_sign`

`handoff_allowed` is evidence only. It is not final approval.

## 10. Final policy engine v4-required mode

`shield_v4_required=True` activates the AdamantineOS v4-required gate.

When this mode is active, the final policy engine must reject:

- unverified Shield v4 evidence
- missing v4 receipt data
- v3 downgrade receipts
- missing verification summaries
- weaker signature policy
- missing Orchestrator signature summary
- missing component signature summary
- malformed component summaries

Default compatibility mode remains `shield_v4_required=False` until a later controlled integration step enables v4-required mode for the full runtime path.

V4.10-F does not change that default or enable it automatically in the v2
runtime host. The direct verifier-to-final-policy proof is not a deployed
wallet or SDK integration claim. Final policy evaluates Shield, WSQK v2,
Q-ID, Adaptive Core, AI Gateway, replay, wallet policy, and human gates in
that order before final approval.

## 11. Verification order

The verifier must process checks cheap to expensive:

1. bounded exact-JSON snapshot and receipt/component/bundle preflight;
2. bounded replay/denylist inputs, registry/freshness validation, and every
   key's resolution, role, status, and validity-window checks;
3. exact canonical receipt/bundle byte limits and hash-integrity checks;
4. all six classical callbacks, then all six ML-DSA callbacks, then optional
   FN-DSA callbacks in canonical bundle order;
5. independent signature summaries and embedded-summary consistency;
6. for the audited wrapper, exact atomic durable acknowledgement before return;
7. evidence result, never final approval; replay-state mutation remains caller-owned;
8. independent AdamantineOS final-policy gates.

The normative work limits and cheap-to-expensive sequencing are in
[performance/DoS v1](CONTRACTS/shield_v4_performance_dos_envelope_v1.md).
The release-facing audited API is
`verify_shield_v4_orchestrator_receipt_with_audit`; the ordinary verifier
remains available without a mandatory audit sink. Audit privacy, count/byte
limits, and ACK semantics are in
[audit v1](CONTRACTS/shield_v4_verification_audit_v1.md).

Malformed input must be rejected before expensive signature work.

## 12. Tests that lock this boundary

The current AdamantineOS Shield v4 tests are:

- `tests/contracts/test_shield_orchestrator_receipt_v4_contract.py`
- `tests/integrations/test_shield_orchestrator_receipt_v4_verifier.py`
- `tests/integrations/test_shield_v48h_fn_dsa_optional_evidence.py`
- `tests/integrations/test_shield_v48h_fn_dsa_signed_message_kat.py`
- `tests/integrations/test_shield_v49_external_verification_contract.py`
- `tests/policy/test_final_policy_engine_shield_v4_required.py`
- `tests/test_adamantineos_shield_v4_docs_lock.py`
- `tests/integrations/test_shield_v410b_verification_audit.py`
- `tests/integrations/test_shield_v410c_performance_dos_envelope.py`
- `tests/test_v410f_final_verifier_proof_pack.py`

These tests lock contract validation, canonical signature-bundle order, whole-receipt and direct-bundle preflight, verifier behavior, trust-registry checks, downgrade rejection, and final-policy v4-required behavior.

## 13. Release status

This document does not claim Shield v4 is released.

Current status: AdamantineOS has a Shield v4 verifier boundary, fixtures, fail-closed trust-registry checks, a v4-required final-policy gate, optional draft FN-DSA/Falcon-1024 verify-only handling, a V4.9-J canonical-order and receipt-wide preflight implementation, and a V4.9-L independent external-contract consumer proof.

V4.10-F consolidates the [final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
and [independent release status](ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md).
Package version deliberately remains 3.0.0 for this proof-only step. The
current v4 candidate is not the historical v3.0.0 release. Post-commit standard,
six-node native, performance, fresh-ZIP, and final release gates remain separate.
