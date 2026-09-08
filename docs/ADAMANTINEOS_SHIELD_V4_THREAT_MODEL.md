# AdamantineOS Shield v4 Threat Model

Author attribution: DarekDGB
Status: Shield v4 V4.10-F final verifier candidate proof lock
Scope: AdamantineOS-side Shield v4 receipt verification and final-policy boundary

## 1. Security objective

AdamantineOS must treat Shield v4 as verifiable evidence only.

The objective is to prevent signed evidence from becoming signed execution authority. AdamantineOS remains the final execution boundary, and Shield v4 must not sign transactions, broadcast transactions, or change DigiByte consensus.

## 2. Assets protected

This boundary protects:

- AdamantineOS final policy authority
- Shield v4 receipt integrity
- component-verdict integrity
- context-hash binding
- request-id binding
- replay protection
- key-role separation
- trust-registry validity
- downgrade resistance from v4 to v3
- wallet and external-integrator safety assumptions

## 3. Trust boundaries

### 3.1 Trusted boundary

AdamantineOS local policy code, local verifier code, and the configured trusted Shield v4 key registry are inside the trusted boundary.

### 3.2 Untrusted boundary

Incoming Shield receipts, component verdicts, embedded signature policies, metadata, handoff hints, wallet UI claims, network data, AI-generated text, and upstream summaries are untrusted until verified.

V4.10-B audit output is also non-authoritative. AdamantineOS emits only the
frozen, bounded `shield.verification_audit.v1` tagged union through an injected
atomic append-only sink. Raw request IDs and key IDs are domain-separated
hashes; receipts, signatures, keys, payloads, nonces, metadata, personal data,
and exception text are prohibited. A missing durable acknowledgement fails
closed before any evidence result escapes. Audit capture never mutates replay
state and never grants final approval, signing, execution, or broadcast power.

### 3.3 Evidence boundary

Even after verification, Shield v4 remains evidence. It cannot produce final approval.

The compatibility default remains `shield_v4_required=False`. A trusted
caller must explicitly select `shield_v4_required=True`; F does not enable
it automatically in the v2 runtime host. Direct verifier/final-engine tests
are not evidence of deployed wallet integration. Wallets consume only the
AdamantineOS final outcome, not an upstream receipt's ALLOW or handoff hint.

Deployment-owned trust anchors, replay persistence, audit-sink durability, and
raw transport parsing limits remain prerequisites, not properties supplied by
an in-memory test fixture or acknowledgement.

## 4. Attacker goals

The verifier and final policy engine must defend against:

- submitting a v3 receipt where v4 is required
- stripping ML-DSA and presenting a weaker classical-only policy
- presenting FN-DSA/Falcon evidence as if it were ML-DSA
- flipping an authenticated FN-DSA `standard_profile` after signing
- claiming optional FN-DSA in embedded summaries when AdamantineOS did not independently verify it
- replaying a previously valid receipt
- changing context hash after signing
- changing request id after signing
- changing component id after signing
- changing reason ids after signing
- changing handoff state after signing
- forging or tampering with receipt hashes
- splicing valid signatures from another receipt
- using a component key as an Orchestrator key
- using an Orchestrator key as a component key
- using a revoked key
- using a key outside its validity window
- rolling back a key registry to reactivate revoked authority
- injecting `sign`, `broadcast`, `override`, or `final_approval` fields
- causing expensive PQC verification before cheap structural rejection
- relying on an implicit TEST-ONLY verifier when no signature backend is configured
- forging or drifting embedded `component_signature_results` away from AdamantineOS independent verification

## 5. Required fail-closed rules

AdamantineOS must deny when:

- the receipt is not a mapping
- the schema is not `shield.receipt.v2`
- `contract_version` is not `4`
- the canonicalization profile is not `shield-v4-canon.v1`
- `policy.v1` is not satisfied
- required signatures are missing
- signature bundles contain duplicate algorithms
- unknown algorithms appear
- unsupported or flipped standard profiles appear
- the key registry is invalid
- key lookup fails
- keys are revoked
- key validity windows fail
- receipt freshness fails
- replay is detected
- the expected context hash does not match
- the expected request id does not match
- any component signature summary is missing, incomplete, or drifted from independently verified optional FN-DSA evidence
- embedded `component_signature_results` do not match the independently computed AdamantineOS component verification summaries
- no explicit signature verifier backend is configured for receipt verification
- any upstream artifact tries to carry final execution authority

## 6. Algorithm threat controls

Policy `policy.v1` requires both `classical-ed25519` and `ml-dsa`.

ML-DSA is the algorithm formerly known as CRYSTALS-Dilithium.

FN-DSA is based on Falcon and is separate from ML-DSA. FN-DSA can be optional evidence, but it must never compensate for failed or missing required signatures. The V4.8H-D profile is `fips206-draft-falcon1024-v1`; it exists to isolate the draft Falcon-1024 direction from future FIPS 206 final profile changes and is not a final-standard claim.

This prevents algorithm-substitution and downgrade attacks.

## 7. Replay and freshness threats

Freshness fields must be signed:

- `request_id`
- `freshness_nonce`
- `not_before`
- `not_after`

Replay protection must reject duplicate request ids within the verifier's tracked window. Replay state must only be updated after a receipt verifies successfully.

## 8. Authority-bypass threats

The most dangerous attack is not a bad signature. The most dangerous attack is a valid-looking signed receipt that tricks downstream code into treating Shield as final authority.

AdamantineOS must therefore reject authority-bypass keys and preserve the rule:

`handoff_allowed` is evidence only; it is not final approval.

Final approval is only produced by the AdamantineOS final policy engine after all required evidence and local gates pass.

## 9. DoS and performance threats

PQC verification can be expensive. V4.10-C freezes the exact limits and order
in `docs/CONTRACTS/shield_v4_performance_dos_envelope_v1.md`.

The verifier traverses untrusted input once into an exact built-in JSON
snapshot. It rejects cycles, depth above 16, more than 4,096 nodes, any text
field above 8,192 bytes, cumulative UTF-8 scalar/key bytes above 131,072, and
integers outside signed 64-bit range before copying or canonicalization. Empty
generic strings and keys remain valid JSON snapshot values; later field schemas
reject emptiness where required.

All six bundle shapes, algorithms, profiles, replay/denylist inputs, registry
entries, freshness windows, key status, and key resolution pass before receipt
or bundle canonicalization and hash work. Exact canonical receipt and bundle
limits are then checked before any callback. Callback waves are globally
ordered: all six classical calls, all six ML-DSA calls, then optional FN-DSA
calls. Required-only work is exactly 12 callbacks and six PQC callbacks. Full
optional evidence is exactly 18 callbacks and 12 PQC callbacks.

The API receives a parsed mapping and trusted transport hash, so this boundary
does not claim a raw JSON transport-byte limit. The transport parser must apply
its own raw-message limit.

## 10. Real backend proof over-claim threats

Threat: deterministic fake-backend CI is described as proof that live liboqs ML-DSA has run.

Required controls:

- default CI is described as interface-contract and fail-closed proof only;
- live liboqs ML-DSA verification is an optional gated job using `SHIELD_V4_REAL_OQS=1`;
- the gated job must use a JUnit not-skipped guard so import-skipped OQS tests cannot read as a pass;
- V4.8G-R4 adds an optional gated full-receipt proof that injects live liboqs ML-DSA signatures into every component verdict and the Orchestrator receipt, then verifies the receipt through AdamantineOS;
- release-grade real-backend proof remains part of the V4.10 proof pack before public release claims.


## 11. Out of scope

Shield v4 does not modify DigiByte consensus.

Shield v4 does not sign wallet transactions.

Shield v4 does not broadcast wallet transactions.

Shield v4 does not replace user confirmation, wallet policy, replay gates, or AdamantineOS final policy.

## 12. Current phase status

V4.8H-D and V4.8H-E are complete. They lock AdamantineOS verify-only handling
for optional FN-DSA/Falcon-1024 evidence, the live Falcon-1024 gated proof path,
and profile-summary drift rejection. V4.10-B added the frozen durable audit
boundary. V4.10-C adds bounded work, exact callback waves, and the pinned
performance/DoS regression job without changing verification authority, replay
state, final policy, runtime execution, signing, or broadcast behavior.

V4.10-F consolidates the [final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
and [release-status record](ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md).
It deliberately retains package version 3.0.0 without relabeling historical
v3 evidence. The native gate requires all six exact nodes with zero skips,
failures, or errors; its classical callbacks remain TEST-ONLY. This is not
production Ed25519, HSM, FIPS-validated deployment, or final FIPS 206 proof.
Post-commit CI, fresh-ZIP verification, and explicit release authorization
remain separate. Floating native dependencies do not prove reproducible builds.

## V4.8H-E live-Falcon and summary-profile threat lock

V4.8H-E adds the live Falcon-1024 verification path for FN-DSA draft-profile evidence and treats profile-summary drift as an explicit fail-closed threat.

AdamantineOS must deny:

- component or Orchestrator FN-DSA signatures under any unsupported profile;
- `component_signature_results` that claim algorithms without matching `verified_standard_profiles`;
- `component_signature_results` that claim a profile AdamantineOS did not independently verify;
- live backend disabled-mechanism, malformed binary material, or native liboqs exceptions;
- any attempt to use FN-DSA as rescue logic, transaction-signing authority, broadcast authority, consensus authority, or final FIPS 206 proof.
