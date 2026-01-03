# Adamantine Wallet OS — Architecture Lock

**Author:** DarekDGB  
**Status:** Locked (Phases 11–14)  
**License:** MIT

This document defines which parts of Adamantine Wallet OS are **frozen**, which are
**extension points**, and what guarantees developers can rely on.

---

## 🔒 Locked Foundations (Do Not Bypass)

The following layers are **architectural invariants**.  
They are enforced by code, tests, and documentation.

### 1) Signing & Execution Gate (Phase 11)
- **Single public entrypoint:** `execute_signing_intent(...)`
- **Enforced order:**  
  `Watch-only → EQC → Shield → WSQK → Runtime`
- **No direct signing is supported**
- **Non-bypassable** (regression tested)

If this flow is broken, security is broken.

---

### 2) Storage & Persistence Model (Phase 12–13)
- **WalletStorage** interface is canonical
- **WalletBatch** defines atomicity
- Backends:
  - In-memory (tests / dev)
  - SQLite (desktop / server)
- Storage is **backend-agnostic**
- Business logic must not depend on storage internals

---

### 3) Wallet & Account State
- Wallet state is persisted via `WalletStateStore`
- Account metadata via `AccountStore`
- Account creation via `AccountFactory`
- **Watch-only is persisted data**, not UI logic

Signing gates query state; they do not invent it.

---

### 4) DigiDollar (DD) Storage (Phase 14)
- Namespaced storage (`DD_*`)
- Structures:
  - `DD_POSITION`
  - `DD_BALANCE`
  - `DD_OUTPUT`
- Atomic updates via `WalletBatch`
- **No protocol rules in storage**

DD storage is a *ledger view*, not a policy engine.

---

### 5) Read-only Client APIs (Phase B)
- `WalletQueryAPI` is **read-only**
- Safe for UI / mobile / web
- No mutation, no signing, no network

Clients may read freely but cannot act directly.

---

## 🧩 Extension Points (Safe to Build On)

The following are intentionally extensible:

- UI / client layers (iOS / Android / Web)
- Additional storage backends (e.g. mobile secure stores)
- DD protocol logic (mint / redeem) **above storage**
- Analytics & telemetry (outside signing trust boundary)
- Network intelligence (DQSN)

Extensions must **respect locked layers** above.

---

## 🚫 Explicitly Out of Scope
- Blockchain consensus rules
- Cryptographic primitives themselves
- “Shortcut” signing paths
- Browser-based seed or signing flows
- Business logic inside storage layers

---

## 🧠 Design Principle

> **EQC decides. Shield verifies. WSQK executes. Runtime enforces.  
> Storage persists. Queries observe.**

Adamantine Wallet OS prioritizes **provable safety over convenience**.

---

## Final Note

These locks exist so developers can build confidently **without fear that the
foundation will shift under them**.

Foundations are locked.  
Everything above is free to evolve.
