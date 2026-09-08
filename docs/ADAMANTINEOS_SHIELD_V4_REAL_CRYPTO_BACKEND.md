# AdamantineOS Shield v4 Real Crypto Backend Contract

Author attribution: DarekDGB

## Status

This document locks the AdamantineOS real-crypto verification boundary for Shield v4.
It connects AdamantineOS Shield v4 receipt verification to deployment-controlled real
signature backends without making AdamantineOS a transaction signer.

V4.10-F records this as an unreleased verifier candidate with an independent
no-bump decision: package 3.0.0 remains unchanged. See the
[final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
and [release status](ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md).

## Boundary lock

AdamantineOS remains the final execution boundary.

AdamantineOS verifies Shield v4 evidence, but it must not:

- sign Shield receipts;
- sign DigiByte transactions;
- broadcast transactions;
- change DigiByte consensus;
- accept Shield evidence as final approval.

A verified Shield v4 `ALLOW` receipt remains evidence only. AdamantineOS continues its
own final policy checks after evidence verification.

## Algorithm lock

Shield v4 policy `policy.v1` requires:

- `classical-ed25519`;
- `ml-dsa`, formerly CRYSTALS-Dilithium.

`fn-dsa`, based on Falcon, is optional evidence only. FN-DSA/Falcon is not ML-DSA and
must never override failure of the required algorithms. V4.8H-D locks the draft Falcon-1024
standard profile as `fips206-draft-falcon1024-v1` for verify-only evidence handling.
This is profile separation for future FIPS 206 movement, not a final-standard claim.

## Verify-only adapter

AdamantineOS exposes a verify-only backend contract in:

```text
src/adamantine/v1/integrations/shield_v4_real_crypto_backend.py
```

The adapter is intentionally verify-only. It contains no signing method because
AdamantineOS must not become a Shield signer or transaction signer.

The optional OQS ML-DSA verify-only backend lives in:

```text
src/adamantine/v1/integrations/shield_v4_oqs_mldsa_backend.py
```

It lazily imports `oqs` only when used, so normal CI and non-OQS deployments do not
silently depend on local machine crypto state. If OQS is missing, disabled, or lacks
the locked mechanism, AdamantineOS fails closed.

## OQS ML-DSA mapping

For Shield v4 `policy.v1`, the optional OQS backend maps:

```text
Shield algorithm: ml-dsa
OQS mechanism:    ML-DSA-65
```

The mechanism is deliberately locked for this backend. A caller cannot silently swap
`ML-DSA-44`, `ML-DSA-87`, Falcon/FN-DSA, or another mechanism behind the Shield
policy name.

## CI proof levels and gated real-liboqs job

Default package CI proves AdamantineOS real-backend verifier interface behavior,
fail-closed parsing, exception wrapping, and Shield v4 policy integration with deterministic
backends. That default CI does not claim to execute live liboqs ML-DSA.

Live liboqs verification is optional at installation and explicitly required
by the dedicated release-proof job. AdamantineOS gains no hard native
dependency. The current six-node command and both enable flags are below;
the historical ML-DSA-only command is not the current release gate.

The guard fails if the real-OQS job collects zero tests, skips any testcase, or records any
failure/error.

V4.8G-R4 adds a second gated proof module that injects real liboqs ML-DSA signatures into every component verdict and the Orchestrator receipt, then verifies the full receipt through AdamantineOS with a hybrid verifier. The classical path remains deterministic TEST-ONLY evidence in that focused proof; the ML-DSA path is live liboqs when the gated workflow is green and the JUnit guard reports zero skipped tests.

AdamantineOS also requires callers to inject a signature verifier explicitly. An unconfigured signature backend is rejected as `SIGNATURE_BACKEND_NOT_CONFIGURED`; the verifier does not silently fall back to TEST-ONLY logic.

AdamantineOS independently re-verifies component signatures and rejects receipts whose embedded `component_signature_results` drift from the independently computed summaries.

A public claim that live liboqs ML-DSA verified through AdamantineOS requires
that gated job to pass with `skipped == 0`; release-grade real-backend proof remains a
V4.10 release gate.

## V4.8H-E OQS Falcon-1024 verify-only mapping

V4.8H-E adds an optional verify-only OQS Falcon-1024 backend for live FN-DSA draft-profile evidence:

```text
src/adamantine/v1/integrations/shield_v4_oqs_falcon_backend.py
tests/integrations/test_shield_v48h_e_oqs_falcon_backend.py
tests/integrations/test_shield_v48h_e_real_oqs_falcon_full_chain.py
```

The backend mapping is locked as:

```text
Shield algorithm: fn-dsa
standard_profile: fips206-draft-falcon1024-v1
OQS mechanism:    Falcon-1024
```

AdamantineOS remains verify-only. The Falcon backend verifies Shield evidence; it does not sign transactions, broadcast, change DigiByte consensus, or grant upstream final authority. FN-DSA remains optional evidence and is not final FIPS 206 proof.

V4.8H-E extends the dedicated PQC workflow so it sets both `SHIELD_V4_REAL_OQS=1` and `SHIELD_V4_REAL_OQS_FALCON=1`, then runs the ML-DSA proof, the ML-DSA full-chain proof, and the Falcon-1024 full-chain proof in the same guarded JUnit report:

```text
SHIELD_V4_REAL_OQS=1 SHIELD_V4_REAL_OQS_FALCON=1 PYTHONPATH=src python -m pytest --override-ini addopts='' \
  tests/integrations/test_shield_v48g_real_oqs_mldsa_backend.py \
  tests/integrations/test_shield_v48g_real_oqs_full_chain.py \
  tests/integrations/test_shield_v48h_e_real_oqs_falcon_full_chain.py \
  -q --junitxml=shield-v4-real-oqs-results.xml
python scripts/assert_real_oqs_junit_not_skipped.py shield-v4-real-oqs-results.xml \
  --min-tests 6 \
  --require-testcase "tests/integrations/test_shield_v48g_real_oqs_mldsa_backend.py::test_v48g_real_oqs_mldsa65_adamantineos_verify_only_backend_positive_and_negatives" \
  --require-testcase "tests/integrations/test_shield_v48g_real_oqs_full_chain.py::test_v48g_r4_real_oqs_mldsa_full_chain_verifies_through_adamantineos" \
  --require-testcase "tests/integrations/test_shield_v48g_real_oqs_full_chain.py::test_v410b_real_oqs_mldsa_full_chain_requires_durable_audit_ack" \
  --require-testcase "tests/integrations/test_shield_v48g_real_oqs_full_chain.py::test_v48g_r4_real_oqs_mldsa_full_chain_rejects_tampered_orchestrator_mldsa" \
  --require-testcase "tests/integrations/test_shield_v48h_e_real_oqs_falcon_full_chain.py::test_v48h_e_real_oqs_mldsa_and_falcon_full_chain_verifies_through_adamantineos" \
  --require-testcase "tests/integrations/test_shield_v48h_e_real_oqs_falcon_full_chain.py::test_v48h_e_real_oqs_full_chain_rejects_tampered_falcon_signature"
```

A public live Falcon-1024 AdamantineOS claim requires that dedicated workflow to finish green with `skipped == 0`, `failures == 0`, and `errors == 0` for the guarded report.

V4.10-B adds the durable-ACK node to the earlier five-node set. The current
gate is exactly six nodes, with `tests=6 skipped=0 failures=0 errors=0 required=6`.
The native positives verify live ML-DSA-65 and draft Falcon-1024 across the
five components and Orchestrator. Classical callbacks remain TEST-ONLY.
The embedded-Falcon tamper node rejects receipt-integrity drift before native
signature verification; it is not a native Falcon rejection measurement.
Production Ed25519, HSM, key custody, side-channel safety, and FIPS-validated
deployment are not proven by this hybrid harness. Upstream native dependencies
remain floating, so this is not a reproducible-build claim.

## Frozen real-signature input

Every real signature is verified over the exact byte string:

```text
DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT
<domain_tag>
<signed_payload_hash>
<algorithm>
<standard_profile>
<key_id>
<key_version>
```

Rules:

- UTF-8 encoding only;
- line separator is LF (`\n`);
- no trailing newline;
- `signed_payload_hash` must be lowercase SHA-256 hex;
- `domain_tag` must be one of the frozen Shield v4 signing domains;
- `standard_profile` is authenticated in the message bytes so FN-DSA/Falcon-1024 cannot be flipped to another profile after signing;
- `algorithm`, `key_id`, and `key_version` must match the verifier contract and
  trusted registry entry; `standard_profile` is authenticated in each signature
  entry and checked against the verifier allow-list, not a registry-entry field.

## V4.8H-D FN-DSA verify-only handling

AdamantineOS treats FN-DSA as optional hybrid evidence under `policy.v1`:

- FN-DSA absent is allowed when `classical-ed25519` and `ml-dsa` both verify;
- FN-DSA present and valid is recorded as additional evidence;
- FN-DSA present but invalid, malformed, wrong-role, wrong-payload, unsupported-profile, or missing from the trusted registry is rejected fail-closed;
- a valid FN-DSA signature cannot rescue failed or missing `classical-ed25519` or `ml-dsa`;
- embedded `component_signature_results` must match AdamantineOS independent verification and cannot falsely claim or hide FN-DSA evidence.

V4.8H-E adds a live-Falcon proof path for draft Falcon-1024 evidence. The locked behavior remains verify-only contract handling, standard-profile binding, deterministic fixtures, and KAT coverage for the `fips206-draft-falcon1024-v1` profile; no final FIPS 206 claim is made.

## Binary encoding lock

Real ML-DSA and FN-DSA/Falcon-1024 signatures and public keys are binary. AdamantineOS real backend adapters
use explicit unpadded base64url encoding with the prefix:

```text
b64u:<unpadded-base64url-bytes>
```

Rules:

- real binary signatures use `b64u:`;
- real OQS public keys use `b64u:` in the trust registry;
- padding characters (`=`) are rejected;
- malformed base64url is rejected before calling a crypto backend;
- historical 64-character deterministic test digests remain test fixtures only.

## Fail-closed material boundary

AdamantineOS real verification must reject deterministic test material before calling
a production backend.

Rejected examples include:

- key ids beginning with `test-`;
- public keys containing `TEST-ONLY`.

There is no fallback from real verification mode to TEST-ONLY deterministic HMAC
verification.

## Durable audit and performance scope

Release integrations requiring durable audit call
`verify_shield_v4_orchestrator_receipt_with_audit` with an injected atomic
append-only sink; an exact durable acknowledgement is required before return.
The ordinary verifier remains separate. Both paths leave replay-state mutation
to the trusted caller. In-memory test acknowledgements do not prove disk durability.

The [performance contract](CONTRACTS/shield_v4_performance_dos_envelope_v1.md)
bounds the parsed snapshot and global callback waves. Its pinned benchmark uses
deterministic callbacks and excludes native latency. F does not add a signing
method or private-key resolver, change the compatibility default
`shield_v4_required=False`, or wire v4 automatically into the runtime host.

## Third-party attribution

When a real backend is selected, repository-level attribution belongs in:

```text
THIRD_PARTY_NOTICES.md
```

The notice must identify the backend family, clarify that no third-party PQC source is
vendored unless explicitly stated, and keep author attribution as DarekDGB.
