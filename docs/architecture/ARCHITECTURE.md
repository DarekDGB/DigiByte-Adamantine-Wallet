# Architecture — Adamantine Wallet OS (Diagrams)

This folder contains architecture diagrams for Adamantine Wallet OS.

**Start here first:**
- 📌 `DIAGRAMS_INDEX.md` (authoritative map of what is current vs legacy)
- 📌 `docs/ARCHITECTURE_LOCK.md` (what is frozen, what is extensible)

---

## Architecture Diagram Index

### 1. Signing Gate Flow (Authoritative)
**Purpose:** The single enforced path for signing/execution.
📄 `signing-gate-flow.md`

---

### 2. EQC Decision Flow (Authoritative)
**Purpose:** EQC as decision-only: context → verdict.
📄 `eqc-decision-flow.md`

---

### 3. WSQK Execution Scope (Authoritative)
**Purpose:** WSQK as execution-only: scoped, time-bound execution.
📄 `wsqk-execution-scope.md`

---

### 4. Storage Architecture (Authoritative)
**Purpose:** WalletStorage / WalletBatch, namespaces, backends.
📄 `storage-architecture.md`

---

### 5. DigiDollar Storage Model (Authoritative)
**Purpose:** DD_POSITION / DD_BALANCE / DD_OUTPUT and atomic batch updates.
📄 `dd-storage-model.md`

---

### 6. Query API Boundary (Authoritative)
**Purpose:** Read-only client access (no signing, no mutation).
📄 `query-api-boundary.md`

---

### 7. Watch-only Data Path (Authoritative)
**Purpose:** Persisted watch-only enforcement at the signing gate.
📄 `account-watch-only-path.md`

---

## Supporting / Partial (Context Only)

### EQC · WSQK · Runtime Narrative
**Purpose:** Additional narrative context (not authoritative vs locked diagrams).
📄 `eqc-wsqk-runtime.md`

---

## Legacy / Historical (Archived)

These files are preserved for history and live under `legacy/`:

- 📄 `legacy/transaction-defense-flow.md`
- 📄 `legacy/wallet-protection-stack.md`
- 📄 `legacy/adaptive-core-learning-loop.md`
- 📄 `legacy/threat-signal-lifecycle.md`
- 📄 `legacy/wallet-only-minimal-flow.md`
- 📄 `legacy/policy-engine-flow.md`

---

## Notes

If any diagram conflicts with:
- code behavior
- regression tests
- `docs/ARCHITECTURE_LOCK.md`

Then the locked artifacts win.
