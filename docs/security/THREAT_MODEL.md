# Adamantine Wallet OS — Threat Model (EQC · WSQK · Runtime)

**Author:** DarekDGB  
**License:** MIT

This document defines the threat model for **Adamantine Wallet OS** and explains
what is **in scope**, what is **out of scope**, and what is **structurally blocked**
by the core invariant:

> **EQC decides. WSQK executes. Runtime enforces.**  
> No signing, minting, or authorization may occur without an EQC `ALLOW` verdict.

This is an **OS-level wallet security model**, not a browser/extension model.

---

## 1) Assets We Protect

### High-value assets
- **Authority to execute** wallet actions (send / mint / redeem / sign)
- **User funds** (DGB, DigiAssets, DigiDollar)
- **User identity hooks** (Q-ID interfaces, recovery interfaces)
- **Policy integrity** (EQC rules + policy packs)
- **Execution integrity** (WSQK scope binding + single-use guard)
- **User intent** (prevent covert or coerced execution)

### Security goals
- Block execution in hostile runtimes **by design**
- Ensure actions are **context-bound** and **wallet-scoped**
- Prevent replay, reuse, and silent escalation of authority
- Make “unsafe by default” impossible to slip in unnoticed

---

## 2) Trust Boundaries

### Trusted components (within the repo’s security boundary)
- EQC engine + deterministic classifiers
- Policy evaluation (default policy + optional policy packs)
- WSQK scope binding + session guard
- Runtime orchestrator enforcement
- Tests that lock invariants

### Untrusted / hostile surfaces
- Browser runtime environments
- Browser extensions
- Injected scripts / DOM tampering
- Malware in userland space
- Remote nodes / network conditions (treated as adversarial signals)

---

## 3) Attacker Model

We assume attackers can:
- Trick users via UI deception or spoofing
- Inject code in browser contexts (extensions / supply-chain / XSS)
- Attempt replay (repeat a previously allowed execution)
- Attempt context substitution (approve one context, execute another)
- Attempt wallet substitution (approve wallet A, execute wallet B)
- Attempt policy weakening via “helpful” PRs or refactors
- Attempt “developer bypass” by calling internal functions directly

We do **not** assume:
- Perfect endpoint security
- Perfect network conditions
- Trusted nodes
- Trusted browser environments

---

## 4) In-Scope Threat Classes

### T1 — Browser wallet / extension compromise
**Goal:** steal seed / sign malicious tx in hostile runtime  
**Defense:** EQC invariants deny browser/extension execution for sensitive actions.

### T2 — UI deception / user intent hijack
**Goal:** user thinks they approve X but actually executes Y  
**Defense:** EQC context hashing + WSQK context-binding prevents substitution.

### T3 — Replay attacks (reuse authority)
**Goal:** reuse once-approved authority repeatedly  
**Defense:** WSQK nonce single-use + TTL, enforced by guard.

### T4 — Context mismatch attacks
**Goal:** approve context A, execute context B  
**Defense:** WSQK is bound to `context_hash` emitted by EQC.

### T5 — Wallet mismatch attacks
**Goal:** approve wallet A, execute wallet B  
**Defense:** WSQK scope is wallet-scoped; guard enforces wallet match.

### T6 — Policy weakening / silent downgrade
**Goal:** merge code that makes policy looser  
**Defense:** tests + “packs only tighten security” rule + explicit exports & invariants.

### T7 — Developer bypass path
**Goal:** call lower-level execution functions directly  
**Defense:** Runtime orchestrator is the enforcement gate; tests assert no bypass.

---

## 5) Out-of-Scope (Explicit)

These are not “ignored”; they are handled by other layers or future modules.

- Hardware wallet implementation details (future backend interface)
- OS-level malware / root compromise (can still degrade UI trust)
- Supply-chain compromise of build pipeline (separate CI hardening topic)
- Consensus-level attacks on DigiByte itself (consensus-neutral by design)
- Node censorship attacks (handled by node manager + reputation logic)

---

## 6) Structural Guarantees

### G1 — No bypass path
No execution reaches WSQK unless EQC returns `ALLOW`.

### G2 — Authority is not a long-lived secret
WSQK is scoped, context-bound, TTL-limited, and single-use.

### G3 — Deterministic decisions
EQC decisions are deterministic for a given context.

### G4 — Fail closed
Under uncertainty or hostile runtime signals, the system denies or requires step-up.

---

## 7) Required Evidence (Tests)

This repo must always keep tests proving:

- Browser context is denied with explicit reason codes
- Extension context is denied with explicit reason codes
- Step-up is required for high-impact actions (mint/redeem)
- WSQK cannot be replayed (nonce consumed)
- WSQK blocks wallet mismatch
- WSQK blocks context mismatch
- Policy packs cannot loosen security (they can only tighten)

---

## 8) Summary

Adamantine Wallet OS security is enforced by architecture:

- **EQC decides** (pure, deterministic, no side effects)
- **WSQK executes** (scoped, bound, single-use authority)
- **Runtime enforces** (no bypass path)

This makes Adamantine fundamentally different from browser wallets and extensions,
which cannot enforce OS-level invariants by design.
