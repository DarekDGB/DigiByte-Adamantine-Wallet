# EQC / WSQK API (Names + Invariants Lock)

**Author:** DarekDGB  
**License:** MIT

This document freezes the names, invariants, and minimal interface shapes of the enforcement system.

---

## Core invariant

> **EQC decides → WSQK executes → Runtime enforces**

### No bypass path
There must be **no code path** that allows signing or execution without:
1) EQC verdict = `ALLOW`
2) WSQK authority issued for the same context
3) Runtime enforcement verifying scope + TTL + nonce

---

## Signing Gate (Non-Negotiable)

All signing in Adamantine Wallet OS must go through the **Shield Signing Gate**:

**EQC → Shield → WSQK**

No direct signing APIs are supported. Any signing attempt that does not pass
EQC `ALLOW` and Shield `ALLOW` is blocked, including watch-only accounts.

**Single entrypoint:** `execute_signing_intent(...)` in  
`core/runtime/shield_signing_gate.py`

---

## Minimal interface shapes (stable names)

### EQC

**Input:** `ExecutionContext`
- immutable context describing the action intent
- includes all relevant parameters (amount, destination, asset type, network, etc.)

**Output:**
- `verdict: VerdictType` (`ALLOW`, `DENY`, `STEP_UP`)
- `context_hash: bytes` (deterministic hash of canonical context)
- `signals: dict` (deterministic signals / reasons)

EQC rules:
- no side effects
- no signing
- no key generation
- deterministic output for same context

---

### WSQK

WSQK represents execution authority after EQC approval.

**Input:**
- `context_hash`
- `scope` (wallet + action scope)
- `ttl` (time-to-live)
- `nonce` (single-use replay protection)

Rules:
- single-use authority (nonce enforced)
- bound to a specific `context_hash`
- not reusable across contexts

---

## Explicit rule: no signing without ALLOW

Signing must be impossible unless:
- EQC returns `ALLOW`
- WSQK authority exists and matches `context_hash`
- Runtime validates TTL + nonce + scope

---

## Runtime enforcement

Runtime is the only route to sensitive execution.
It must guarantee:
- EQC evaluated first
- WSQK only reachable after ALLOW
- execution blocked otherwise
