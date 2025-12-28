# 🔷 DigiByte Adamantine Wallet OS  
### *Quantum-Secure Wallet OS • Shield-Integrated • Multi-Client Architecture*  
**Architecture by @DarekDGB — MIT Licensed**

---

# 🌌 Overview

**DigiByte Adamantine Wallet OS** is not a traditional cryptocurrency wallet.  
It is a **full Wallet Operating System (Wallet-OS)** designed to unify:

- Multi-client DigiByte wallet (Android, iOS, Web)  
- DigiAssets v3 engine  
- DigiDollar minting module  
- Q-ID (PQC identity system)  
- Guardian Wallet (User Protection Layer)  
- Quantum Wallet Guard (QWG)  
- Shield Bridge (Sentinel → DQSN → ADN → QWG → Guardian)  
- Adaptive Core v2 (Learning, Fusion & Signal Correlation)  
- Enigmatic Layer-0 communications  
- Node integration (local + DigiMobile)  
- Risk Engine  
- Telemetry  
- End-to-end test layers  
- **EQC (Equilibrium Confirmation)** — deterministic decision layer  
- **WSQK (Wallet-Scoped Quantum Key)** — scoped execution authority  

Adamantine Wallet OS is built to serve as the **primary gateway** for DigiByte’s next era:  
quantum-resistant, modular, secure, intelligent, and entirely open-source.

---

## 🔗 External MIT Modules Acknowledgment

Adamantine does **not** reimplement or claim ownership of external DigiByte community projects.  
It provides clean integration layers for existing MIT-licensed modules, including:

- **Enigmatic (Layer-0 messaging)** — created by @JohnnyLaw  
- **DigiMobile / Node tools** — also created by @JohnnyLaw  

Adamantine uses *adapters* to connect with these systems when they are available.  
All credit for the underlying protocols belongs to their original authors.  
Adamantine’s architecture simply enables them to work together within a unified Wallet-OS.

---

# 🧱 Architecture Summary

Adamantine Wallet OS is structured as:

```
DigiByte-Adamantine-Wallet-OS/
│
├── clients/               # Android, iOS, Web clients (UI & app logic)
├── core/                  # Wallet engine, EQC, WSQK, shield bridge, assets
├── modules/               # DigiDollar, DigiAssets, Enigmatic, telemetry, integrations
├── docs/                  # Full whitepapers for each subsystem
├── config/                # Guardian rules, network parameters
├── tests/                 # End-to-end and unit tests
└── .github/workflows/     # CI for Android • iOS • Web • Docs
```

Each subsystem is completely modular, versioned, explainable, and independently testable.

---

# 🔐 Core Security Architecture (EQC + WSQK)

Adamantine enforces an OS-level security invariant:

> **EQC decides. WSQK executes. Runtime enforces.**

There is no bypass path.

### 🔹 EQC — Equilibrium Confirmation

EQC is the **deterministic decision engine** of Adamantine Wallet OS.

It:
- evaluates an immutable execution context  
- runs classifiers and explicit policy rules  
- returns a final verdict (`ALLOW`, `DENY`, `STEP_UP`)  

EQC:
- has no side effects  
- does not sign  
- does not generate keys  
- does not execute actions  

EQC produces:
- a verdict  
- a context hash  
- a signal bundle  

### 🔹 WSQK — Wallet-Scoped Quantum Key

WSQK defines **execution authority** after EQC approval.

WSQK authority is:
- scoped to a wallet and specific action  
- bound to an EQC-approved context hash  
- time-limited (TTL)  
- single-use (nonce enforced)  
- non-reusable across contexts  

There is no static private key to steal.

### 🔹 Runtime Enforcement

A runtime orchestrator guarantees:

- EQC is always evaluated first  
- WSQK cannot be reached without `ALLOW`  
- execution is blocked otherwise  

All invariants are enforced in code and locked by CI tests.

---

---

## Design Motivation vs Enforcement

Some documents in this repository (notably simulated attack reports)
were written before EQC and WSQK were implemented.

These documents describe *why* a policy-based, context-aware Wallet OS
was required.

EQC and WSQK are the architectural response to those threats:
- EQC evaluates actions under explicit context and policy
- WSQK enforces the resulting verdict at runtime

The simulations are design inputs, not retroactive justifications.

---


# 🛡️ Adamantine & The DigiByte Quantum Shield

Adamantine is the **only DigiByte wallet** designed to deeply integrate all 5 layers of the Shield:

```
   Sentinel AI v2        (Anomaly Detection)
   DQSN v2               (Network Health & Entropy)
   ADN v2                (Active Defence Playbooks)
   QWG                   (User-Side Transaction Guard)
   Guardian Wallet       (User Warnings & Protection)
   Adaptive Core v2      (Learning & Fusion)
                ↓
     Adamantine Wallet OS (Final Execution Layer)
```

Adamantine is where **all shield intelligence becomes real protection**.

---

# 🧬 Wallet OS: Core Philosophy

Adamantine is built on six principles:

1. **Quantum Security First** — PQC-ready architecture via Q-ID, QWG, and WSQK.  
2. **Explainability** — every decision (including EQC verdicts) is deterministic and auditable.  
3. **Modularity** — each subsystem is isolated and upgrade-ready.  
4. **Multi-Client Parity** — Android, iOS, and Web behave identically.  
5. **Separation of Concerns** — decision (EQC), authority (WSQK), and execution are isolated.  
6. **Consensus-Neutrality** — Adamantine never changes DigiByte consensus rules.

---

# 📱 Clients (Android • iOS • Web)

```
clients/
├── android/
├── ios/
└── web/
```

Each client receives:

- wallet engine API  
- UI screens  
- Shield & Guardian integration  
- DigiAssets v3 rendering  
- DigiDollar minting UX  
- Node selection via Node Manager  
- PQC identity hooks for Q-ID  
- EQC-driven decision feedback  

The wallet OS layer guarantees identical behaviour across all three environments.

---

# 🔧 Core Infrastructure

```
core/
├── wallet_engine/
├── eqc/                  # Equilibrium Confirmation engine
├── wsqk/                 # Wallet-Scoped Quantum Key execution layer
├── digiassets/
├── digiassets_v3/
├── guardian_adapter/
├── shield_bridge/
└── utxo_manager.py, fee_estimator.py, state, builders...
```

### 🔹 **Wallet Engine**
Implements:

- wallet state  
- UTXO selection  
- balance tracking  
- transaction building  
- fee estimation  
- sync interfaces  

### 🔹 **EQC Engine**
`core/eqc/`

Handles:
- execution context evaluation  
- deterministic classifiers  
- explicit policy enforcement  
- final action verdicts  

### 🔹 **WSQK Layer**
`core/wsqk/`

Handles:
- EQC-bound execution scope  
- time-limited, single-use authority  
- nonce-based replay protection  
- execution gating (no EQC → no execution)  

### 🔹 **DigiAssets Engine**
`core/digiassets/`

Handles:

- metadata parsing  
- asset creation  
- asset transfer logic  
- asset state tracking  

### 🔹 **DigiAssets v3 Engine**
`core/digiassets_v3/`

Next-generation asset protocol:

- improved metadata structure  
- deterministic encoding  
- new ownership rules  
- future-proof PQC adaptability  

### 🔹 **Guardian Adapter**
Connects wallet actions to:

- Guardian Wallet warnings  
- QWG behavioural rules  
- Shield risk conditions  

### 🔹 **Shield Bridge**
The critical module linking Adamantine to the **Quantum Shield**:

- reads Sentinel, DQSN, ADN outputs  
- evaluates node health  
- evaluates safe mode  
- updates wallet runtime guard decisions  

---

# 🪙 DigiDollar (DD) — Native Minting Engine

```
modules/dd_minting/
```

**DigiDollar is a concept originally introduced by DigiByte founder Jared Tate.**  
Adamantine implements an open-source minting engine to support and extend that vision.

Capabilities:

- mint DigiDollar tokens (DD)  
- update ledgers  
- validate supply rules  
- integrate with the wallet engine  
- execute only after EQC approval  
- expose a clean API for clients  

DigiDollar in Adamantine is:

- **non-inflationary**  
- **deterministic**  
- **fully auditable**  

Concept credit: **Jared Tate**  
Architecture and engine implementation: **@DarekDGB (MIT-licensed)**

---

# 🧩 DigiAssets v3

```
core/digiassets_v3/
```

Includes:

- new parsing engine  
- new metadata layer  
- new execution engine  
- examples & reference spec  

This is one of the strongest future-facing upgrades in the entire repo.

---

# 🔐 Q-ID (Quantum Identity System)

```
docs/identity/
```

Q-ID provides:

- PQC identity  
- signature layering  
- recovery paths  
- identity-bound asset permissions  

100% ready for Falcon / Dilithium.

---

# 💬 Enigmatic Layer-0 Messenger

```
modules/enigmatic_chat/
```

Integrated via JohnnyLaw’s MIT-licensed Layer-0 messaging stack.

Adamantine includes:

- message encoder  
- channel manager  
- protocol adapter  

This enables **encrypted, fee-based, blockchain-aligned messaging** inside the wallet.

---

# 📡 Analytics & Telemetry

```
modules/analytics_telemetry/
```

Lightweight, anonymised, and optional.

Tracks:

- crashes  
- UI patterns  
- performance metrics  
- shield interaction signals  

Always compliant with user privacy.

---

# 🌐 Node Integration

```
core/shield_bridge/
core/node_manager.py
modules/integrations/digimobile.py
```

Adamantine connects to:

- local DigiByte Core nodes  
- DigiMobile nodes (MIT-licensed by JohnnyLaw)  
- fallback node pools  
- node reputation scoring  
- health-based priority selection  

Tests include:

- `test_node_manager_priority_logic.py`  
- `test_node_manager_errors.py`  
- `test_node_manager_digimobile_preference.py`

This is **enterprise-grade node routing**.

---

# 🛡️ Risk Engine

```
core/shield_bridge/risk_engine.py
docs/risk/*
```

Evaluates:

- network risk  
- reorg probability  
- mempool anomalies  
- timing patterns  
- node health  

Outputs flow into:

- Guardian Wallet warnings  
- QWG  
- Adaptive Core signals  

---

# 🔄 Shield Integration (Full Stack)

Adamantine is the **execution layer** of the shield:

```
DQSN  →  Sentinel  →  ADN  →  QWG  →  Guardian Wallet  →  Adamantine Wallet OS
```

Receives:

- metrics  
- anomalies  
- defence strategies  
- transaction decisions  
- guardianship actions  
- adaptive learning signals  

Making Adamantine the **first quantum-secure wallet OS** in DigiByte history.

---

# 🔍 Documentation

Located in:

```
docs/
```

Includes:

- architecture  
- shield layers  
- risk model  
- identity system  
- DigiAssets v3 spec  
- DigiDollar  
- node design  
- EQC & WSQK architecture  

➡️ Security Simulation Reports (01–03) are available in docs/security/

> Note: Security Simulation Reports (01–03) are threat-driven design inputs that
> predate EQC and WSQK. They document adversarial scenarios that motivated the
> architecture, not post-hoc mappings of current enforcement behavior.


### 🔐 Security Architecture

- [Trust Wallet Attack Immunity Checklist](docs/security/trust-wallet-attack-immunity-checklist.md)

## Architecture

Adamantine Wallet OS is designed as a **user-first protection layer** that operates
at the wallet level without modifying blockchain consensus or cryptography.

The architecture focuses on:
- Local-first enforcement and user sovereignty  
- Layered defense against user error, malware, and manipulation  
- Optional network intelligence without centralization  
- Safe failure behavior under uncertainty or offline conditions  

📐 **[Architecture Overview](docs/architecture/ARCHITECTURE.md)**  

---

# 🧪 Test Suite

```
tests/
```

Includes coverage for:

- wallet engine  
- EQC and WSQK invariants  
- node manager  
- risk engine  
- DigiAssets v3  
- shield bridge  
- guardian adapter  
- full wallet flows  

Production-level test depth.

---

# 🧙 Contribution Guidelines

See `CONTRIBUTING.md`.

Key rules:

- no module removal  
- no collapsing structure  
- no consensus changes  
- no black-box ML  
- no breaking shield layers  
- tests must stay green  

Only structured improvements accepted.

---

# 📜 License

MIT License  
© 2025 **DarekDGB**

This architecture is free to use with mandatory attribution.
