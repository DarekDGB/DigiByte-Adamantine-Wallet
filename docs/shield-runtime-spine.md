# Shield Runtime Spine — Adamantine Wallet OS

## Purpose

This document defines the **Shield + Adaptive Core** as the **primary security spine**
of Adamantine Wallet OS.

EQC and WSQK are critical enforcement components, but they **do not operate alone**.
All sensitive wallet activity is evaluated through a **5-layer defensive Shield**
with an **Adaptive (Immune) Core** that learns, escalates, and hardens behavior over time.

This is not a feature.
This is the security model.

---

## High-Level Runtime Flow

```
User / App Intent
        ↓
EQC — Policy & Context Gate
        ↓
Shield Engine (5 Layers)
        ↓
Adaptive Core (Immune Response)
        ↓
WSQK — Controlled Execution
```

> **Invariant:**  
> WSQK MUST NOT execute if either EQC or Shield returns a blocking verdict.

---

## The 5-Layer Shield

The Shield is a **multi-signal risk evaluation system**.
Each layer contributes signals; no single layer is trusted in isolation.

| Layer | Role |
|-----|-----|
| Sentinel | Baseline behavioral + structural checks |
| DQSN | Network, environment, and signal correlation |
| ADN | Anomaly & deviation detection |
| QAC | Context integrity and assurance evaluation |
| Immune Interface | Adaptive Core feedback & escalation |

The Shield aggregates signals into a **single risk decision** with explainability.

Related docs:
- `architecture/legacy/architecture/legacy/wallet-protection-stack.md`
- `architecture/legacy/architecture/legacy/transaction-defense-flow.md`
- `architecture/legacy/architecture/legacy/threat-signal-lifecycle.md`

---

## Adaptive Core (Immune System)

The Adaptive Core is **stateful**.

It does not decide individual transactions in isolation.
It observes **patterns over time** and modifies future behavior.

Capabilities include:
- Risk accumulation and decay
- Escalation after repeated medium-risk events
- Temporary or persistent restrictions
- Guardian / step-up enforcement
- Cooldowns and safety locks

Related docs:
- `adaptive-core-learning-*.md`
- `failure-modes-and-safeguards.md`

---

## Relationship to EQC and WSQK

### EQC (Execution Qualification Core)
- Establishes **policy, permissions, and context validity**
- Has **no side effects**
- Produces a deterministic verdict

### Shield + Adaptive Core
- Evaluate **risk, behavior, and temporal patterns**
- Can override execution even if EQC allows
- Provide explainable security decisions

### WSQK (Wallet Secure Quantum Kernel)
- Executes only after **all security gates pass**
- Enforces isolation and controlled execution

Related doc:
- `eqc-wsqk-runtime.md`
- `architecture/legacy/architecture/legacy/policy-engine-flow.md`

---

## Why This Matters

Most wallets rely on:
- Static rules
- Single-layer checks
- One-time authorization

Adamantine Wallet OS introduces:
- Defense-in-depth
- Cross-layer signal aggregation
- Time-aware immune responses
- Enforced execution gates

This architecture is designed to remain effective as threats evolve,
not just against known attack classes.

---

## Summary

- EQC defines **if** something is allowed
- Shield defines **whether it is safe**
- Adaptive Core defines **how the system learns**
- WSQK defines **how execution happens**

Together, they form a **Wallet Operating System**, not just a wallet.

Shield + Adaptive Core are the security spine.
