# Shield v4 Verification Audit v1

Author attribution: DarekDGB

**Status:** FROZEN  
**Schema:** `shield.verification_audit.v1`  
**Scope:** AdamantineOS verification evidence only

This contract records Shield v4 verification without changing verification,
replay, final-policy, signing, execution, or broadcast authority. The existing
public verifier remains available unchanged. Release integrations requiring
durable audit use `verify_shield_v4_orchestrator_receipt_with_audit`.

## Privacy boundary

Records contain domain-separated SHA-256 hashes of request IDs and key IDs,
never the raw identifiers. The domains are:

```text
DGB-SHIELD-V4-AUDIT-REQUEST-ID\n
DGB-SHIELD-V4-AUDIT-KEY-ID\n
```

Inputs are NFC-normalized UTF-8 before hashing. Each component record hashes
that component artifact's request ID; the outer receipt record hashes the outer
request ID. Records must not contain receipts, payloads, signatures, public or
private keys, seeds, nonces, metadata, personal data, or exception text.

## Exact tagged union

Every record contains exactly `schema_version`, `event_type`, `verifier_id`,
`verification_timestamp`, `verification_passed`, and `reason_id` plus exactly
one of these event payloads:

- `verification_preflight`: `artifact_type`,
  `expected_artifact_schema_version`, `artifact_transport_hash`,
  `expected_request_id_hash`, `expected_context_hash`,
  `required_policy_version`, `minimum_registry_version`;
- `signature_verification`: `artifact_type`, `artifact_schema_version`,
  `artifact_id`, `artifact_hash`, `request_id_hash`, `context_hash`,
  `policy_version`, `registry_version`, `key_id_hash`, `key_version`,
  `algorithm`, `standard_profile`;
- `artifact_verification`: the validated artifact fields above without the four
  key/algorithm/profile fields.

No field is nullable and no `unknown` sentinel exists. The verifier ID is
`adamantineos.v1`; Orchestrator artifact ID is `shield_orchestrator`; component
artifact IDs are the frozen component IDs. Timestamp is the injected canonical
exact-second RFC3339 UTC verification time.

Allowed reasons are `V4_VERIFY_OK`, `V4_CONTRACT_INVALID`,
`V4_CONTEXT_MISMATCH`, `V4_REQUEST_MISMATCH`, `V4_HASH_MISMATCH`,
`V4_DOWNGRADE_REJECTED`, `V4_AUTHORITY_BYPASS`, `V4_POLICY_INVALID`,
`V4_REGISTRY_INVALID`, `V4_FRESHNESS_INVALID`, `V4_REPLAY_REJECTED`,
`V4_SIGNATURE_INVALID`, `V4_BACKEND_UNAVAILABLE`, and
`V4_BACKEND_FAILURE`.

## Durable append and limits

One verification creates one ordered, non-empty atomic batch. Maximums are 24
records, 2,048 UTF-8 canonical JSON bytes per record, and 49,152 canonical JSON
bytes for the `{"records":[...]}` batch envelope. The sink receives an immutable
`tuple[bytes, ...]` of individually validated exact canonical records and
exposes append only; it must durably commit all records or none.

The batch digest is SHA-256 over:

```text
DGB-SHIELD-V4-VERIFICATION-AUDIT-BATCH:shield.verification_audit.v1\n
<canonical JSON {"records":[...]} object>
```

The required exact acknowledgement is a built-in dictionary (subclasses are
rejected) with exactly the keys `schema_version`, `batch_sha256`,
`record_count`, and `durably_committed`. It carries
`schema_version='shield.verification_audit.append_ack.v1'`, matching
`batch_sha256`, exact integer `record_count`, and `durably_committed=True`.
Sink exception, malformed or mismatched acknowledgement, and non-true durable
commit raise `ShieldV4AuditSinkError('V4_AUDIT_SINK_FAILURE')` without a chained
cause. No evidence result escapes that failure.

Audit fields never become execution authority. The wrapper does not write or
reorder replay state and does not call the final-policy or runtime execution
paths.

V4.10-C preserves this tagged union, reason allowlist, acknowledgement, and
batch contract. Successful required-only verification emits six classical
signature records in canonical artifact order followed by six ML-DSA records
in the same order. When valid optional FN-DSA is present in all bundles, six
FN-DSA records follow. This is 12 signature records for required-only evidence
or 18 for full optional evidence, plus the existing preflight and terminal
records. No audit record is emitted for a cryptographic callback that did not
occur.

Receipt containers are untrusted operation surfaces. The audited wrapper first
creates the shared bounded exact-JSON snapshot. Dictionary/list subclasses,
cycles, over-depth, over-node, over-text, over-scalar-byte, and over-integer
inputs fail before canonicalization and callbacks. An unexpected
receipt-controlled exception produces only one sanitized failed preflight
record and then raises
`ShieldV4AuditedVerificationError('V4_CONTRACT_INVALID')` without a chained
cause. Raw exception details never enter the record or public error. Invalid
trusted caller parameters (expected hashes/request ID, timestamp, registry floor,
or transport hash) remain programmer errors rejected before receipt operation
and before any sink call.
