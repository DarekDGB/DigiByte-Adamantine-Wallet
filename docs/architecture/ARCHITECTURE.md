# Architecture Overview

This document is the **entry point** for the Adamantine Wallet OS architecture.
It provides an ordered view of the system design, threat model, and protection layers.

Adamantine focuses on **user protection at the wallet layer**.
It does not modify blockchain consensus, cryptography, or protocol rules.

Wallet-layer protection is enforced through a strict execution model:
**EQC decides → WSQK executes → Runtime enforces**.
No sensitive action is permitted unless explicitly allowed by policy.

---

## How to Read These Documents

The diagrams are ordered from **runtime behavior** to **supporting systems**.
If you are short on time, read them in order from top to bottom.

Some diagrams represent earlier conceptual flows, while newer ones reflect
the current EQC / WSQK / Runtime execution model. All remain valid within scope.

Each document is:
- Scoped to wallet-layer behavior
- Designed to be testnet-friendly
- Written to avoid centralized trust assumptions

---

## Architecture Diagram Index

### 1. Transaction Defense Flow
**Purpose:** What happens when a user initiates a transaction.

📄 `transaction-defense-flow.md`

---

### 2. Wallet Protection Stack
**Purpose:** What runs locally in the wallet vs optional network intelligence.

📄 `wallet-protection-stack.md`

---

### 3. Adaptive Core Learning Loop
**Purpose:** How learning improves protection without taking control.

📄 `adaptive-core-learning-loop.md`

---

### 4. Threat Signal Lifecycle
**Purpose:** How threat signals are created, anonymized, shared, and expired.

📄 `threat-signal-lifecycle.md`

---

### 5. Deployment Topology
**Purpose:** Where components run and how the system behaves offline.

📄 `deployment-topology.md`

---

### 6. Wallet-Only Minimal Flow
**Purpose:** Baseline protection with no network dependencies.

📄 `wallet-only-minimal-flow.md`

---

### 7. Policy Engine Flow
**Purpose:** How user-defined policies constrain transaction behavior.

📄 `policy-engine-flow.md`

---

### 8. Failure Modes and Safeguards
**Purpose:** How the wallet behaves under failure or uncertainty.

📄 `failure-modes-and-safeguards.md`

---

## Scope and Non-Goals

**In scope:**
- Wallet-layer protection
- User intent validation
- Risk-aware transaction handling
- Local-first enforcement
- Policy-based execution control

**Out of scope:**
- Blockchain consensus changes
- Cryptographic algorithm design
- Mining or validator logic
- Protocol governance

---

## Notes

This architecture is intended to evolve through testing and review.
All components are designed to be optional, composable,
and respectful of user sovereignty.
