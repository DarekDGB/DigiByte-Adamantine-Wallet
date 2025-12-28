# Adamantine Wallet OS — Invariants Checklist (EQC · WSQK · Runtime)

**Author:** DarekDGB  
**License:** MIT

This checklist defines the **non-negotiable invariants** of Adamantine Wallet OS.
If any invariant breaks, security is broken — even if features still “work”.

Core rule:

> **EQC decides. WSQK executes. Runtime enforces.**  
> No execution path may reach WSQK unless EQC returns `VerdictType.ALLOW`.

---

## A) Execution Flow Invariants (Hard)

### A1 — No bypass path
- [ ] All sensitive execution routes go through **RuntimeOrchestrator**
- [ ] There is no direct “sign/mint/send” code path that skips EQC
- [ ] Internal helper functions do not become public bypass APIs

### A2 — EQC is evaluated first
- [ ] EQC decision occurs before any signing/minting/authorization step
- [ ] EQC produces a deterministic `context_hash`
- [ ] EQC has **no side effects** (no signing, no keys, no network mutation)

### A3 — WSQK cannot exist without EQC `ALLOW`
- [ ] WSQK scope binding requires EQC `ALLOW`
- [ ] WSQK scope binding uses EQC `context_hash`
- [ ] Step-up or deny verdicts never produce WSQK authority

---

## B) Hostile Runtime Invariants (Hard)

### B1 — Browser context is denied (explicit)
- [ ] `device_type="browser"` is denied for sensitive actions
- [ ] Denial includes `ReasonCode.BROWSER_CONTEXT_BLOCKED`

### B2 — Extension context is denied (explicit)
- [ ] `device_type="extension"` is denied for sensitive actions
- [ ] Denial includes `ReasonCode.EXTENSION_CONTEXT_BLOCKED`

### B3 — Fail closed
- [ ] Unknown / missing runtime signals produce DENY or STEP_UP (never silent ALLOW)

---

## C) WSQK Authority Invariants (Hard)

### C1 — Wallet-scoped
- [ ] WSQK scope includes `wallet_id`
- [ ] Execution blocks if `wallet_id` mismatch

### C2 — Action-scoped
- [ ] WSQK scope includes `action`
- [ ] Execution blocks if `action` mismatch

### C3 — Context-bound
- [ ] WSQK scope includes `context_hash`
- [ ] Execution blocks if `context_hash` mismatch

### C4 — Time-limited
- [ ] WSQK authority expires via TTL
- [ ] Expired scope blocks execution

### C5 — Single-use (replay-proof)
- [ ] Successful execution consumes nonce
- [ ] Replaying same scope fails deterministically

---

## D) Policy Invariants (Hard)

### D1 — Default policy never becomes “more permissive” silently
- [ ] Default rules deny hostile runtimes (browser/extension)
- [ ] High-impact actions (mint/redeem) require STEP_UP (with requirements)

### D2 — Policy packs only tighten security
- [ ] Packs can only move outcomes toward stricter results:
  - ALLOW → STEP_UP → DENY
- [ ] Packs cannot weaken base policy behavior

### D3 — Pack evaluation is deterministic
- [ ] Pack ordering is stable (deterministic registry ordering)
- [ ] Conflicts merge deterministically (DENY wins, then STEP_UP, then ALLOW)

---

## E) Export / API Stability Invariants (Hard)

### E1 — Stable public exports
- [ ] `core.eqc` exports stable public surface (engine/context/verdict/decision/codes)
- [ ] `core.wsqk` exports stable public surface (bind/guard/session/scope/errors)
- [ ] Runtime orchestrator imports only from stable surfaces where possible

### E2 — Backward compatible refactors
- [ ] Internal refactors do not break tests or public imports
- [ ] If a name changes, a compatibility alias remains (until intentional major bump)

---

## F) Test Coverage Requirements (Hard)

These tests must remain green:
- [ ] Browser deny reason code present
- [ ] Extension deny reason code present
- [ ] Mint/redeem STEP_UP contains requirements
- [ ] WSQK replay blocked
- [ ] WSQK wallet mismatch blocked
- [ ] WSQK context mismatch blocked
- [ ] Policy packs only tighten security test

---

## Release Rule

No PR may merge if it breaks any “Hard” invariant.
