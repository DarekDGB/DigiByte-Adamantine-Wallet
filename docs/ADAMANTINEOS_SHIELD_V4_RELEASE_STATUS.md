# AdamantineOS Shield v4 Verifier Release Status

Author attribution: DarekDGB
Status: V4.10-F candidate prepared; post-commit verification pending

## Independent version decision

Decision for V4.10-F: deliberate no-bump. `adamantine-wallet-os` remains
`3.0.0`; `pyproject.toml`, import paths, and runtime code are unchanged.
No active runtime `__version__` or server-version field exists to align.
F is a proof/documentation/test step, not a release stamp. The next independent
AdamantineOS release number remains unassigned until its release decision.
It does not automatically reuse the six Shield repositories' `v4.0.0` tag.

The historical AdamantineOS v3.0.0 release and its 925-test proof set do not
describe the current unreleased Shield v4 verifier candidate. Historical
release notes, tag-decision documents, fixtures, and the old Full Integration
Build Ledger are retained unchanged. Their historical approval text does not
authorize a new tag or retagging current main.

## Candidate scope

The [final verifier proof pack](PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
maps shared KATs, component/Orchestrator verification, required policy, optional
FN-DSA no-rescue behavior, canonical order, trust/freshness/replay controls,
durable audit, work budgets, and final-policy authority to executable tests.

AdamantineOS remains verify-only for Shield evidence and the final execution
boundary. A wallet consumes only AdamantineOS final output. The compatibility
default remains `shield_v4_required=False`; callers explicitly select
`shield_v4_required=True` where required. F does not automatically enable that
mode in the v2 runtime host or complete a deployed wallet/SDK integration.
It adds no signing, broadcast, or consensus authority.

## Claims deliberately withheld

- Shield v4 release completion or permission to create/move a tag.
- Final FIPS 206: the locked profile remains `fips206-draft-falcon1024-v1`.
- Production classical Ed25519, HSM, key custody, or FIPS-validated deployment
  proof from the hybrid native tests' TEST-ONLY classical callbacks.
- Native provider latency from the deterministic-callback performance job.
- Byte-identical native builds from floating upstream dependencies.
- Real audit-store durability from an in-memory test acknowledgement.

## Required post-commit gates

| Gate | Requirement |
| --- | --- |
| Standard CI | Full suite; 100% `adamantine` statement coverage; only the three expected ordinary native-module skips |
| Dedicated native proof | Exact six locked nodes, both enable flags, `tests=6 skipped=0 failures=0 errors=0 required=6` |
| Performance/DoS | Exact pinned environment and benchmark PASS |
| Fresh ZIP | Exact delivered candidate, no unrelated drift, embedded/current commit and official Git tree match |

All workflow evidence must bind to the final complete F commit. The controlled
roadmap records preparation results separately from these pending gates.
Only DarekDGB changes GitHub. No release tag is authorized by this document.
