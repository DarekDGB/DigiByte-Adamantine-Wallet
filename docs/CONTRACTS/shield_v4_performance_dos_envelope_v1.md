# Shield v4 Performance and DoS Envelope v1

Author attribution: DarekDGB

Status: FROZEN for V4.10-C
Schema: `shield-v4-v410c-performance-v1`
Repository: `DigiByte-AdamantineOS`
Scope: AdamantineOS Shield v4 verification work only

## Boundary

The release-facing audited verifier accepts an already parsed mapping plus a caller-supplied
trusted transport hash. It therefore cannot claim a limit on the unavailable
raw JSON transport bytes. This contract limits the bounded isolated JSON
snapshot and its exact canonical representation. The transport boundary must
enforce its own raw-message limit before parsing.

AdamantineOS remains the final execution boundary. Shield v4 output is
cryptographically verifiable decision evidence only. This envelope grants no
final approval and no signing, execution, broadcast, or DigiByte consensus
authority.

## Exact input and work limits

The verifier freezes the complete receipt before canonicalization or callback
work. Only exact built-in dictionaries, lists, strings, booleans, signed
integers, and null are accepted. Dictionary and list subclasses are rejected.
Cycles are rejected.

| Limit | Exact maximum |
| --- | ---: |
| Canonical receipt | 131,072 bytes |
| Snapshot UTF-8 scalar and key bytes, cumulative | 131,072 bytes |
| Any JSON text value or object key | 8,192 bytes |
| Any encoded signature or trusted public-key field | 8,192 bytes |
| One canonical signature bundle | 32,768 bytes |
| Container depth | 16 |
| JSON nodes | 4,096 |
| Signed integer range | -2^63 through 2^63-1 |
| Component bundles | 5 |
| Receipt bundles | 1 |
| Signatures per bundle | 2 through 3 |
| Signature bundles | 6 |
| Signature-verifier callbacks | 18 |
| PQC callbacks, ML-DSA plus optional FN-DSA | 12 |
| Trusted registry entries | 64 |
| Replay request identifiers | 4,096 |
| Rejected receipt hashes | 4,096 |

Replay and denylist iterables consume no more than the limit plus one entry.
The cumulative snapshot counter advances during traversal, before copying or
canonicalization, so an input such as 4,096 values of 8,192 bytes cannot be
materialized as a trusted snapshot.

## Verification order

The fail-closed order is:

1. bounded exact-JSON snapshot;
2. exact receipt, component, bundle, algorithm, profile, metadata, count, and
   scalar-size preflight for all five components and the receipt;
3. bounded replay and denylist preflight, exact registry validation, freshness,
   key status/window checks, and resolution of every key for all six bundles;
4. exact canonical receipt and bundle byte checks, then receipt/component hash
   integrity checks;
5. all six `classical-ed25519` callbacks in canonical bundle order;
6. all six `ml-dsa` callbacks in canonical bundle order;
7. optional `fn-dsa` callbacks in canonical bundle order when present.

No callback occurs until every bundle and key passes preflight. A callback
counter advances immediately before invocation, so an exception consumes its
work slot. Required-only evidence has exactly 12 callbacks, six of them PQC.
Evidence with FN-DSA in every bundle has exactly 18 callbacks, 12 of them PQC.
Optional evidence cannot rescue a required failure; if present and invalid it
is fatal.

Work-budget, shape, size, cycle, overcount, and duplicate-algorithm failures use
the existing contract-invalid rejection and audit reason. Replay matches,
registry failures, and backend failures retain their existing stable external
states and audit reasons. The audit schema and reason allowlist do not expand.

## Dedicated benchmark

`.github/workflows/shield-v4-performance-dos.yml` pins:

- `ubuntu-24.04`;
- Python `3.11.15`;
- `PYTHONHASHSEED=0`, `TZ=UTC`, and `LC_ALL=C.UTF-8`;
- `actions/checkout` v4.2.2 and `actions/setup-python` v5.4.0 by full commit;
- pip `25.2`, setuptools `80.9.0`, wheel `0.45.1`, pytest `8.4.1`, and
  pytest-cov `6.2.1`.

The built-in benchmark performs 20 warmups and 200 measured iterations for a
required-only audited valid fixture and an over-limit early rejection. It uses
`time.perf_counter_ns` and emits exactly one JSON object containing:

The required native fixture SHA-256 is
`b1031e999b87f61643748848e6d121f153c3cbdc7c87ceef9a62c766bc8b7ced`.
The script checks this digest before JSON parsing or measurement and fails
closed on drift.

- `schema_version`, `repository`, and `fixture_sha256`;
- `environment` with Python, platform, Python hash seed, timezone, and locale;
- `software` with the exact five pinned package versions;
- `warmups=20` and `samples=200`;
- numeric median and p95 milliseconds for `valid` and `oversize_rejection`;
- limits of 50.0 ms and 20.0 ms respectively;
- `status` equal to `PASS` or `FAIL`.

The script exits nonzero when either p95 limit is exceeded or software versions
drift. Environment drift from Python 3.11.15, `PYTHONHASHSEED=0`, `TZ=UTC`, or
`LC_ALL=C.UTF-8` also fails the job. The benchmark uses deterministic test-only
signature callbacks to measure AdamantineOS validation, audit, and orchestration
overhead. It excludes native provider latency. GitHub-hosted runner CPU remains provider-controlled,
so the result is a regression envelope on the pinned job, not a universal
hardware latency guarantee. No benchmark timer or third-party benchmark plugin
runs in standard CI.
