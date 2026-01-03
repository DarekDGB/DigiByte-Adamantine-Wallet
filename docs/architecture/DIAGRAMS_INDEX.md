# Architecture Diagrams Index

**Author:** DarekDGB  
**License:** MIT  
**Status:** AUTHORITATIVE INDEX (Locked)

This file is the **single entrypoint** for all architecture diagrams in
Adamantine Wallet OS.

It clarifies:
- which diagrams are **authoritative**
- which diagrams are **supporting / partial**
- which diagrams are **legacy / historical**
- where new contributors should start

---

## ✅ Authoritative Diagrams (Current Architecture)

These diagrams reflect the **locked architecture** (Phases 11–14 + Query API).
They are enforced by code, tests, and documentation.

### Signing & Execution
- `signing-gate-flow.md`  
  Authoritative signing and execution flow:  
  **Watch-only → EQC → Shield → WSQK → Runtime**

### EQC & WSQK
- `eqc-decision-flow.md`  
  EQC as **decision-only**: Context → Verdict.
- `wsqk-execution-scope.md`  
  WSQK as **execution-only**: scope-bound, time-bound execution.

### Storage & Persistence
- `storage-architecture.md`  
  WalletStorage, WalletBatch, namespaces, and backends.

### DigiDollar (DD)
- `dd-storage-model.md`  
  DD_POSITION / DD_BALANCE / DD_OUTPUT and atomic batch updates.

### Client Read Boundary
- `query-api-boundary.md`  
  Read-only client access via WalletQueryAPI (no signing, no mutation).

### Watch-only Enforcement Path
- `account-watch-only-path.md`  
  Persisted watch-only account metadata enforced by the signing gate.

---

## 🟡 Supporting / Partial Diagrams

These documents provide useful context but are **not authoritative**
for locked signing, execution, or storage rules.

- `eqc-wsqk-runtime.md`  
  Early narrative of EQC / WSQK / Runtime (kept for additional context).

If any supporting doc conflicts with authoritative diagrams or code/tests,
the authoritative diagrams win.

---

## ⚠️ Legacy / Historical Diagrams

The following documents reflect **earlier conceptual stages** of the project.
They are preserved for history but should not be used for implementation decisions.

All legacy diagrams live under:

- `legacy/`

Legacy files:
- `legacy/wallet-only-minimal-flow.md`
- `legacy/policy-engine-flow.md`
- `legacy/transaction-defense-flow.md`
- `legacy/wallet-protection-stack.md`
- `legacy/threat-signal-lifecycle.md`
- `legacy/adaptive-core-learning-loop.md`

---

## 🔒 Rule of Interpretation

If any diagram or document conflicts with:
- code behavior
- regression tests
- `docs/ARCHITECTURE_LOCK.md`

Then the **locked artifacts win**.

---

## Where to Start (New Contributors)

1. `docs/ARCHITECTURE_LOCK.md`
2. `signing-gate-flow.md`
3. `eqc-decision-flow.md`
4. `wsqk-execution-scope.md`
5. `storage-architecture.md`
6. `dd-storage-model.md`
7. `query-api-boundary.md`

Only after that, explore legacy material for background.

---

## Final Note

Adamantine Wallet OS is intentionally documented in **layers**.

This index exists to prevent confusion, drift, and accidental bypass
of locked security invariants.
