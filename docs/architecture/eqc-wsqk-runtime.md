<!--
SUPPORTING / PARTIAL DOCUMENT NOTICE

This document provides helpful context but is NOT authoritative if it conflicts with:
- code behavior
- regression tests
- docs/ARCHITECTURE_LOCK.md
- docs/architecture/DIAGRAMS_INDEX.md
-->

# Adamantine Wallet OS — EQC · WSQK · Runtime Architecture

This document defines the **core execution-security architecture** of
Adamantine Wallet OS.

It explains how **decision**, **authorization**, **authority**, and
**execution** are strictly separated and enforced.

This is an **OS-level security model**, not a browser wallet model.

---

## Core Principle

> **EQC decides. Shield authorizes. WSQK executes. Runtime enforces.**

No signing, minting, or sensitive execution may occur unless this
sequence is satisfied **in order**.

This rule is enforced by:
- architecture
- runtime gates
- test-backed invariants

There are **no bypass paths**.

---

## High-Level Execution Flow

```
[ Request / Intent ]
        |
        v
[ EQC — Equilibrium Confirmation ]
        |
        |  VerdictType.ALLOW only
        v
[ Shield Evaluation ]
        |
        |  Must not block
        v
[ WSQK Scope Binding ]
        |
        |  Wallet + Action + Context Hash
        v
[ Runtime Capability Issuance ]
        |
        |  Scope-bound authority token
        v
[ WSQK Guard (Nonce + Session) ]
        |
        v
[ Execution ]
```

If any stage fails, execution is **explicitly blocked**.

---

## EQC — Equilibrium Confirmation

EQC is the **decision brain** of Adamantine Wallet OS.

EQC:
- evaluates an immutable execution context
- runs deterministic classifiers
- applies explicit policy rules
- produces a deterministic verdict:
  - `ALLOW`
  - `DENY`
  - `STEP_UP`

EQC characteristics:
- no side effects
- no signing
- no key material
- no execution

EQC outputs:
- verdict
- deterministic `context_hash`
- signal bundle used by downstream layers

EQC **must always run first**.

---

## Shield — Authorization Layer

The Shield is the **authoritative authorization gate**.

Shield evaluation:
- occurs **after EQC**
- occurs **before WSQK**
- is **not advisory**

If Shield blocks, execution **must not proceed**, even if EQC allowed.

Shield decisions are:
- bound to a deterministic intent
- evaluated synchronously
- enforced by runtime gates

There are no “soft” Shield failures.

---

## WSQK — Wallet-Scoped Quantum Key Model

WSQK defines **how execution authority exists**.

WSQK is **not a static private key**.

Instead, WSQK authority is:

- scoped to a specific wallet
- scoped to a specific action
- bound to an EQC-approved `context_hash`
- time-limited (TTL)
- single-use when guarded
- non-transferable across contexts

WSQK **cannot exist** unless EQC has already returned `ALLOW`.

---

## Runtime Capability (Execution Authority)

Execution under WSQK **requires a runtime capability**.

Runtime capabilities:
- are unforgeable tokens
- are issued only by runtime gates
- are never created by callers
- are bound to a WSQK scope hash
- may have finite lifetime

Missing, malformed, expired, or mismatched capabilities
**must block execution**.

This prevents:
- confused deputy attacks
- scope reuse
- privilege escalation

---

## WSQK Guard — Single-Use Execution

WSQK execution is protected by a guard enforcing:

- session validity
- TTL enforcement
- single-use nonce consumption (replay protection)

Once execution succeeds:
- the nonce is consumed
- replay is impossible by construction

Authority becomes **one-time permission**, not a reusable secret.

---

## Runtime Orchestrator

The runtime orchestrator is the **enforcement spine**.

It guarantees:
- EQC is evaluated first
- Shield is enforced
- WSQK cannot be reached without approval
- execution is blocked otherwise

This applies to:
- external calls
- internal calls
- developer-written code paths

Even trusted code **cannot bypass** these gates.

---

## Why Browser Wallets Cannot Enforce This

Browser wallets and extensions:

- run inside hostile environments
- rely on long-lived keys or seeds
- cannot enforce execution invariants
- cannot prevent architectural bypass

Adamantine Wallet OS enforces security
**by construction**, not by convention.

---

## Cryptography Is an Implementation Detail

Cryptography is intentionally abstracted.

This architecture supports:
- classical signing
- PQC KEM wrapping
- hardware-backed execution
- future cryptographic upgrades

Without changing:
- EQC
- Shield
- WSQK
- runtime invariants

This allows development even on constrained environments
(e.g. mobile-only workflows).

---

## Security Philosophy

Security does not come from:
- trust
- reputation
- UI prompts
- extensions
- static secrets

Security comes from:
- explicit authority
- context binding
- separation of concerns
- enforced execution flow
- test-backed invariants

Adamantine Wallet OS is built as a
**security operating system**, not a wallet app.

---

**Author:** DarekDGB  
**License:** MIT  
**Status:** Architecture Frozen
