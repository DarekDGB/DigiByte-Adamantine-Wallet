# AdamantineOS Shield v4 Test Matrix

Author attribution: DarekDGB
Status: Shield v4 V4.9-L independent external-contract consumer proof lock
Scope: AdamantineOS Shield v4 contract, external-contract consumer, verifier, final-policy v4-required tests, and real-backend verifier interface proofs

## 1. Current Shield v4 test files

| Area | Test file | Purpose |
| --- | --- | --- |
| Contract and fixtures | `tests/contracts/test_shield_orchestrator_receipt_v4_contract.py` | Locks Shield v4 receipt shape, hashes, component verdict shape, canonical signature-bundle order, downgrade rejection, and authority-bypass rejection. |
| Verifier and trust registry | `tests/integrations/test_shield_orchestrator_receipt_v4_verifier.py` | Locks verifier acceptance/rejection, receipt-wide preflight, trusted key registry behavior, replay rejection, freshness, key role binding, and signature-summary behavior. |
| Final policy v4-required mode | `tests/policy/test_final_policy_engine_shield_v4_required.py` | Locks AdamantineOS final policy enforcement when `shield_v4_required=True`. |
| Documentation lock | `tests/test_adamantineos_shield_v4_docs_lock.py` | Locks required Shield v4 documentation and boundary wording. |
| V4.9-L external-verifier contract consumer | `tests/integrations/test_shield_v49_external_verification_contract.py` | Pins the byte-identical Orchestrator V1 fixture and locks independent AdamantineOS positive, negative, trust-provenance, and evidence-only verification. |
| Real backend interface contract | `tests/integrations/test_shield_v4_real_crypto_backend_contract.py` | Locks real verifier backend input validation, `b64u:` material, strict bool returns, and fail-closed backend exception behavior. |
| OQS ML-DSA adapter contract | `tests/integrations/test_shield_v4_oqs_mldsa_backend.py` | Locks optional OQS `ML-DSA-65` verify-only adapter behavior with deterministic fakes and native-exception wrapping. |
| V4.8G real-backend interface integration | `tests/integrations/test_shield_v4_real_backend_integration_hardening.py` | Locks real-backend interface wiring with deterministic backends, test-only fallback rejection, tamper rejection, and evidence-only AdamantineOS behavior. |
| V4.8G live liboqs gated proof | `tests/integrations/test_shield_v48g_real_oqs_mldsa_backend.py` | Skipped by default; in a dedicated `SHIELD_V4_REAL_OQS=1` job with installed `oqs`/liboqs, proves live `ML-DSA-65` verify-only behavior and wrong-length fail-closed handling. |
| V4.8G-R4 live liboqs full-receipt proof | `tests/integrations/test_shield_v48g_real_oqs_full_chain.py` | Skipped by default; in the dedicated real-OQS job, injects live liboqs ML-DSA signatures into all component verdicts plus the Orchestrator receipt and verifies the full receipt through AdamantineOS. |
| V4.8H-D FN-DSA optional evidence and V4.9-J order preflight | `tests/integrations/test_shield_v48h_fn_dsa_optional_evidence.py` | Locks optional draft FN-DSA/Falcon-1024 evidence, no rescue, canonical order, required presence, whole-bundle structural preflight, and zero trust/crypto calls for preflight failures. |
| V4.8H-D FN-DSA signed-message KAT | `tests/integrations/test_shield_v48h_fn_dsa_signed_message_kat.py` | Locks the standard-profile-bound real-crypto message bytes for draft Falcon-1024 FN-DSA evidence. |

## 2. Contract matrix

| Control | Expected result | Locked by |
| --- | --- | --- |
| Valid `shield.receipt.v2` ALLOW receipt | Accepted as verified evidence shape | `test_shield_v4_accepts_valid_allow_fixture_contract_boundary` |
| Valid DENY receipt | Accepted but no handoff authority | `test_shield_v4_accepts_valid_deny_fixture_without_granting_execution_authority` |
| v3 receipt submitted where v4 is required | Rejected fail-closed | `test_shield_v4_rejects_downgrade_and_tampered_signature_fixtures` |
| Tampered signature fixture | Rejected fail-closed | `test_shield_v4_rejects_downgrade_and_tampered_signature_fixtures` |
| Wrong schema or contract version | Rejected fail-closed | `test_shield_v4_contract_rejects_non_dict_and_bad_schema_fields` |
| Wrong canonicalization profile | Rejected fail-closed | `test_shield_v4_contract_rejects_non_dict_and_bad_schema_fields` |
| Wrong signature policy | Rejected fail-closed | `test_shield_v4_contract_rejects_non_dict_and_bad_schema_fields` |
| Context hash mismatch | Rejected fail-closed | `test_shield_v4_contract_rejects_context_and_receipt_hash_mismatches` |
| Receipt hash mismatch | Rejected fail-closed | `test_shield_v4_contract_rejects_context_and_receipt_hash_mismatches` |
| Signed payload hash mismatch | Rejected fail-closed | `test_shield_v4_contract_rejects_context_and_receipt_hash_mismatches` |
| Reversed required or optional-first/interleaved signature order | Rejected fail-closed without sorting or repair | `test_v49j_contract_rejects_noncanonical_signature_bundle_order` |
| Forbidden authority fields | Rejected fail-closed | `test_shield_v4_contract_rejects_handoff_authority_and_non_allow_handoff_true` |
| Non-ALLOW receipt with `handoff_allowed=true` | Rejected fail-closed | `test_shield_v4_contract_rejects_handoff_authority_and_non_allow_handoff_true` |
| Missing or invalid component signature results | Rejected fail-closed | `test_shield_v4_contract_rejects_component_result_errors` |
| Missing, duplicate, or unknown component verdicts | Rejected fail-closed | `test_shield_v4_contract_rejects_component_verdict_errors` |

## 3. Verifier and trust-registry matrix

| Control | Expected result | Locked by |
| --- | --- | --- |
| Valid Shield v4 receipt with trusted registry | Verification succeeds | `tests/integrations/test_shield_orchestrator_receipt_v4_verifier.py` |
| Wrong expected context hash | Rejected fail-closed | verifier negative tests |
| Wrong expected request id | Rejected fail-closed | verifier negative tests |
| Stale or not-yet-valid receipt | Rejected fail-closed | verifier freshness tests |
| Duplicate request id / replay | Rejected fail-closed | verifier replay tests |
| Wrong registry version or rollback | Rejected fail-closed | verifier registry tests |
| Missing trusted key | Rejected fail-closed | verifier registry tests |
| Revoked trusted key | Rejected fail-closed | verifier registry tests |
| Signature outside key validity window | Rejected fail-closed | verifier key-window tests |
| Wrong key role | Rejected fail-closed | verifier key-role tests |
| Tampered Orchestrator signature | Rejected fail-closed | verifier signature tests |
| Tampered component signature | Rejected fail-closed | verifier signature tests |
| Real-backend verifier exception | Rejected fail-closed through Shield v4 error hierarchy | `test_v48g_shield_v4_verifier_wraps_signature_verifier_exceptions_fail_closed` |
| Truthy non-bool verifier result | Rejected fail-closed; no truthy coercion | `test_v48g_shield_v4_verifier_rejects_truthy_non_bool_signature_verifier_result` |
| Unconfigured signature backend | Rejected fail-closed as `SIGNATURE_BACKEND_NOT_CONFIGURED` | `test_v48g_r4_shield_v4_verifier_requires_explicit_signature_backend` and `test_v48g_r4_adamantineos_rejects_unconfigured_signature_backend_for_real_fixture` |
| Embedded `component_signature_results` drift from independent AdamantineOS verification | Rejected fail-closed | `test_v48g_r4_shield_v4_verifier_cross_checks_component_signature_results` |
| FN-DSA absent with required signatures valid | Accepted as evidence | `test_v48h_adamantineos_accepts_fn_dsa_absent_and_valid_fn_dsa_present` |
| FN-DSA present and valid with required signatures valid | Accepted as optional evidence | `test_v48h_adamantineos_accepts_fn_dsa_absent_and_valid_fn_dsa_present` |
| FN-DSA valid but required signature invalid | Rejected fail-closed | `test_v48h_fn_dsa_cannot_rescue_required_orchestrator_signature_failure`, `test_v48h_fn_dsa_cannot_rescue_required_component_signature_failure` |
| FN-DSA present but invalid | Rejected fail-closed | `test_v48h_present_invalid_fn_dsa_is_denied_even_when_required_signatures_are_valid` |
| FN-DSA wrong key role or missing registry key | Rejected fail-closed | `test_v48h_fn_dsa_wrong_key_role_is_denied`, `test_v48h_fn_dsa_present_requires_matching_trust_registry_key` |
| FN-DSA unsupported or flipped standard profile | Rejected fail-closed | `test_v48h_unsupported_or_flipped_fn_dsa_standard_profile_is_denied` |
| FN-DSA splice or duplicate algorithm entry | Rejected fail-closed | `test_v48h_fn_dsa_cross_receipt_or_cross_role_splice_is_denied`, `test_v48h_duplicate_fn_dsa_entry_is_denied` |
| FN-DSA summary falsely claimed or hidden | Rejected fail-closed | `test_v48h_component_signature_results_cannot_falsely_claim_or_hide_fn_dsa` |
| Reversed required order in raw Orchestrator or embedded component bundle | Rejected during whole-receipt preflight before trust or crypto | `test_v49j_adamantineos_rejects_noncanonical_receipt_and_component_order_before_trust_or_crypto` |
| Any of the five noncanonical three-entry permutations in raw Orchestrator or embedded component bundle | Rejected during whole-receipt preflight before trust or crypto | `test_v49j_adamantineos_rejects_noncanonical_receipt_and_component_order_before_trust_or_crypto` |
| Duplicate key identity in the top bundle or last embedded component | Rejected during receipt-wide preflight before trust or crypto | `test_v49j_receipt_wide_preflight_rejects_duplicate_key_before_trust_or_crypto` |
| Noncanonical direct private-bundle input | Rejected before trust or crypto | `test_v49j_direct_bundle_verifier_rejects_noncanonical_order_before_trust_or_crypto` |
| Any nonempty supported subset missing a required algorithm | Rejected before trust or crypto | `test_v49j_direct_bundle_verifier_rejects_missing_required_before_trust_or_crypto` |
| Late malformed, duplicate, wrong-profile, wrong-domain, or wrong-hash entry | Rejected after full structural preflight and before trust or crypto | `test_v49j_direct_bundle_verifier_completes_structural_preflight_before_trust_or_crypto` |
| Caller mutates the original bundle after preflight begins | Prepared outer entry snapshots remain authoritative for the cryptographic pass | `test_v49j_direct_bundle_verifier_uses_preflight_snapshots_during_crypto` |
| Exact shared V1 external-verifier fixture | Accepted independently as evidence only with `final_approval=false` | `test_v49l_adamantineos_accepts_external_contract_as_evidence_only` |
| External V1 replay, stale window, revoked key, registry rollback, or denylisted receipt hash | Rejected fail-closed without final authority | `test_v49l_external_contract_rejects_replay_stale_revoked_rollback_and_denylist` |
| External V1 wrong context, unsupported profile, noncanonical order, or weakened policy | Rejected fail-closed | `test_v49l_external_contract_rejects_context_profile_order_and_weakened_policy` |
| Receipt-supplied trust or verifier registry with untrusted key material | Rejected; registry remains verifier-controlled only | `test_v49l_external_contract_registry_is_verifier_controlled_only` |

## 4. Final policy v4-required matrix

| Control | Expected result | Locked by |
| --- | --- | --- |
| Verified v4 receipt and local gates pass | AdamantineOS final decision can allow | `test_shield_v4_required_accepts_verified_v4_receipt_before_local_gates` |
| `shield_v4_required` is malformed | Rejected before evidence evaluation | `test_shield_v4_required_rejects_invalid_mode_shape_before_evidence` |
| Shield evidence is unverified | Rejected fail-closed | `test_shield_v4_required_rejects_unverified_result` |
| Missing v4 receipt | Rejected fail-closed | `test_shield_v4_required_rejects_missing_v4_receipt` |
| v3 downgrade receipt | Rejected fail-closed | `test_shield_v4_required_rejects_v3_downgrade_receipt` |
| Missing verification summary | Rejected fail-closed | `test_shield_v4_required_rejects_missing_verification_summary` |
| Weak policy | Rejected fail-closed | `test_shield_v4_required_rejects_weak_policy` |
| Missing Orchestrator required algorithm | Rejected fail-closed | `test_shield_v4_required_rejects_missing_orchestrator_algorithm` |
| Missing component summary | Rejected fail-closed | `test_shield_v4_required_rejects_missing_component_signature_summary` |
| Component summary missing required algorithms | Rejected fail-closed | `test_shield_v4_required_rejects_component_summary_without_required_algorithms` |
| Default v3-compatible mode | Existing normalized Shield evidence can still pass | `test_default_mode_still_allows_legacy_normalized_shield_evidence` |

## 5. Algorithm matrix

| Algorithm label | Meaning | Current role |
| --- | --- | --- |
| `classical-ed25519` | classical test-only signature path | required in `policy.v1` |
| `ml-dsa` | ML-DSA, formerly CRYSTALS-Dilithium | required in `policy.v1` |
| `fn-dsa` | FN-DSA, based on Falcon; locked draft profile `fips206-draft-falcon1024-v1` | optional evidence only |

FN-DSA/Falcon must never be treated as ML-DSA and must never override failure of a required path. V4.8H-E adds a gated live Falcon-1024 proof path for the draft profile only; it does not claim final FIPS 206 proof.

## 6. Real backend proof levels

| Proof level | CI behavior | Claim allowed |
| --- | --- | --- |
| Default package CI | Uses deterministic verifier backends and fake OQS modules | Proves interface contract, fail-closed behavior, parser hardening, and AdamantineOS evidence-only integration. |
| Gated live liboqs job | Requires `SHIELD_V4_REAL_OQS=1`, `SHIELD_V4_REAL_OQS_FALCON=1`, installed `oqs`/liboqs, JUnit output, and the exact five-node guard with `--min-tests 5` and `skipped == 0` | Proves live `ML-DSA-65` and Falcon-1024 positive verification, an ML-DSA cryptographic tamper negative, and an embedded-Falcon receipt-integrity tamper negative through the AdamantineOS verify-only boundary. |
| V4.10 release gate | Final multi-repo proof pack | Release-grade public claims about real-backend proof. |

AdamantineOS remains verify-only for this path. The real-backend adapter has no `sign_message`, no private-key resolver, and no private-key reference.

## 7. Negative tests still carried into later phases

The following remain important for the full Shield v4 release gate and multi-repo harness:

- full all-component signed ALLOW path across five component repos, Orchestrator, and AdamantineOS
- one component signature missing across the integration harness
- one component wrong key across the integration harness
- one component wrong context hash across the integration harness
- one component v3 downgrade attempt across the integration harness
- Orchestrator receipt signature tampered across the integration harness
- receipt hash tampered but signature valid-looking across the integration harness
- signature valid but signed payload hash mismatch across the integration harness
- replay/stale receipt rejected by injected replay state across the integration harness

V4.8G covers the real-backend interface-contract hardening and gated live-liboqs ML-DSA proof hooks. V4.8H-D covers AdamantineOS verify-only handling for optional FN-DSA/Falcon-1024 evidence. Final public release claims remain gated by the V4.10 proof pack and live workflow evidence with `skipped == 0` where applicable.

## V4.9-J canonical signature-bundle order

V4.9-J requires every raw Orchestrator receipt signature bundle and every embedded component signature bundle to use this exact order:

1. `classical-ed25519`
2. `ml-dsa`
3. optional `fn-dsa`, when present

The contract and verifier never sort or repair received evidence. All embedded bundles and the top-level bundle complete structural, profile, hash, domain, order, required-presence, duplicate-algorithm, and duplicate-key preflight before the first trust-registry lookup or cryptographic verifier call. The private bundle verifier repeats the same preflight for direct internal use.

Required `classical-ed25519` plus `ml-dsa` strict AND remains unchanged. The optional last entry is draft FN-DSA/Falcon-1024 evidence only. Optional-present-invalid is fatal and cannot rescue either required signature path. No public API, schema, policy, profile, domain tag, component role, transaction authority, broadcast authority, consensus rule, or AdamantineOS final-policy boundary changes in V4.9-J.

## V4.9-L independent external-contract consumer proof

V4.9-L copies the Orchestrator `external_verifier_contract_v1_kat.json` fixture byte-for-byte and verifies it independently through the AdamantineOS Shield v4 verifier. The local copy must retain SHA-256 `308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f`.

The positive case must reproduce the complete expected evidence result while retaining `final_approval=false`. The negative matrix covers replay, stale evidence, revoked trust, registry rollback, receipt denylisting, wrong context, unsupported profile, noncanonical signature order, weakened embedded policy, receipt-supplied trust, and verifier-controlled untrusted key material.

The fixture's TEST-ONLY registry is verifier input only. `standard_profile` is authenticated in each signature entry and checked against the verifier allow-list; it is not a registry-entry field. AdamantineOS independently verifies raw receipt and component signatures and does not trust `component_signature_results` as authority.

A wallet consumes only AdamantineOS final output. Raw Orchestrator evidence, the fixture's expected result, and `handoff_allowed` never become signing, broadcast, consensus, or execution authority.

V4.9-L changes no runtime verifier, public API, schema, policy, algorithm, profile, domain tag, component role, dependency, package version, workflow, transaction authority, broadcast authority, consensus rule, or AdamantineOS final-policy boundary.

## V4.8H-E full hybrid matrix

V4.8H-E adds:

| Case | Expected result | Test evidence |
| --- | --- | --- |
| Full receipt with FN-DSA present everywhere | Accepted as evidence only when required signatures also verify | `full_multi_repo_v4_fn_dsa_allow_flow.json`, `test_v48h_adamantineos_accepts_fn_dsa_absent_and_valid_fn_dsa_present` |
| Component summary profile mismatch | Rejected fail-closed | `test_v48h_e_component_signature_result_profile_mismatch_is_denied` |
| Component summary omits matching profile for FN-DSA | Rejected fail-closed | `test_v48h_e_component_signature_result_profile_omission_is_denied` |
| OQS Falcon-1024 verify-only backend contract | Fail-closed on disabled/wrong backend, malformed material, native exceptions, wrong algorithms | `test_shield_v48h_e_oqs_falcon_backend.py` |
| Gated real liboqs Falcon-1024 full-chain proof | Must pass with JUnit `skipped == 0` before any public live-Falcon claim | `test_shield_v48h_e_real_oqs_falcon_full_chain.py` plus `scripts/assert_real_oqs_junit_not_skipped.py` |

The matrix keeps AdamantineOS verify-only and preserves the final execution boundary.
