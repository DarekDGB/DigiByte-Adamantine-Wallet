# Architecture Diagrams Index

**Author:** DarekDGB  
**License:** MIT  
**Status:** AUTHORITATIVE INDEX (Locked)

This file is the **single entrypoint** for all architecture diagrams in
Adamantine Wallet OS.

It clarifies:
- which diagrams are **authoritative**
- which diagrams are **legacy / historical**
- where new contributors should start

---

## ✅ Authoritative Diagrams (Current Architecture)

These diagrams reflect the **locked architecture** (Phases 11–14).
They are enforced by code, tests, and documentation.

### 1) Signing & Execution
- **`signing-gate-flow.md`**  
  Authoritative signing and execution flow:  
  `Watch-only → EQC → Shield → WSQK → Runtime`

### 2) Storage & Persistence
- **`storage-architecture.md`**  
  WalletStorage, WalletBatch, namespaces, and backends.

### 3) DigiDollar (DD)
- **`dd-storage-model.md`**  
  DD_POSITION / DD_BALANCE / DD_OUTPUT and atomic batch updates.

---

## 🟡 Supporting / Partial Diagrams

These diagrams provide useful context but are **not authoritative**
for signing or execution rules.

- `eqc-wsqk-runtime.md`  
  Early description of EQC / WSQK / Runtime before full gate lock.

These may be referenced for understanding, but **do not override**
the authoritative diagrams above.

---

## ⚠️ Legacy / Historical Diagrams

The following documents reflect **earlier conceptual stages** of the project.
They are preserved for history but should not be used for implementation decisions.

Examples:
- `wallet-only-minimal-flow.md`
- `policy-engine-flow.md`
- `transaction-defense-flow.md`
- `wallet-protection-stack.md`
- `threat-signal-lifecycle.md`
- `adaptive-core-learning-loop.md`

These files should include (or be treated as having) a header note:

> “This document reflects an early conceptual design and is not
> authoritative for current signing, execution, or storage behavior.”

---

## 🔒 Rule of Interpretation

If any diagram or document conflicts with:
- code behavior
- regression tests
- `ARCHITECTURE_LOCK.md`

Then the **locked artifacts win**.

---

## Where to Start (New Contributors)

1. `ARCHITECTURE_LOCK.md`
2. `signing-gate-flow.md`
3. `storage-architecture.md`
4. `dd-storage-model.md`

Only after that, explore legacy material for background.

---

## Final Note

Adamantine Wallet OS is intentionally documented in **layers**.

This index exists to prevent confusion, drift, and accidental bypass
of locked security invariants.
