# Adamantine Wallet OS — Runtime Security Invariants

**Author:** DarekDGB  
**Status:** Architecture Freeze  
**Scope:** Runtime execution, signing, and authorization paths

This document defines the **non-negotiable security invariants** of
Adamantine Wallet OS.

If any invariant below is violated, the system must be considered
**security-broken**, even if functionality appears to work.

---

## Core Principle

> **EQC decides. Shield authorizes. WSQK executes. Runtime enforces.**

No execution path may bypass this sequence.

---

## Invariant 1 — EQC Is Mandatory

- Every signing-like or sensitive operation **must** be preceded by an
  EQC (Equilibrium Confirmation) decision.
- If EQC verdict is not `ALLOW`, execution **must not proceed**.
- There are **no fallback paths**.

---

## Invariant 2 — Shield Is Authoritative

- Shield evaluation is **not advisory**.
- If Shield returns a blocking decision, execution **must not proceed**.
- Shield decisions are evaluated **after EQC and before WSQK**.
- Shield decisions are bound to a deterministic `intent_hash`.

---

## Invariant 3 — WSQK Requires Runtime Capability

- WSQK execution **must not occur** without a valid runtime capability.
- Missing, malformed, or invalid capabilities **block execution**.
- Capabilities are issued **only by runtime gates**, never by callers.
- WSQK executors **must explicitly require** a capability parameter.

---

## Invariant 4 — Capability Is Scope-Bound

- Every runtime capability is bound to a specific WSQK scope hash.
- A capability **cannot be reused** for a different scope.
- Scope mismatch **blocks execution** (anti–confused-deputy protection).

---

## Invariant 5 — Capability Has Finite Authority

- Runtime capabilities are:
  - Short-lived
  - Single-purpose
  - Non-transferrable
- Long-lived, ambient, or unlimited authority is **explicitly forbidden**.
- Capability reuse outside its intended execution path **must fail**.

---

## Invariant 6 — Intent Hash Consistency

- Every signing intent produces a deterministic `intent_hash`.
- The same `intent_hash` is:
  - Embedded in EQC context
  - Passed to Shield evaluation
  - Implicitly bound to WSQK execution
- If intent data changes, the hash changes and execution **must not match**.

---

## Invariant 7 — Replay Protection

- WSQK guarded execution supports nonce-based replay prevention.
- Nonces are single-use.
- Reuse of a nonce **must block execution**.
- Replay protection is enforced **before** execution occurs.

---

## Invariant 8 — No Silent Fallbacks

- There are no automatic approvals.
- There are no default bypasses.
- There is no “best effort” execution.

Failure must be **explicit and loud**.

---

## Invariant 9 — Test-Backed Enforcement

- Every invariant above is enforced by CI tests.
- Any change that weakens an invariant **must break tests**.
- Green CI implies **invariant preservation**, not feature correctness alone.

---

## Final Statement

These invariants define the **security contract** of Adamantine Wallet OS.

They are intentionally strict.

Future contributors may extend functionality,  
but **may not weaken or bypass these rules**.

If a proposed change conflicts with this document,  
**this document wins**.
