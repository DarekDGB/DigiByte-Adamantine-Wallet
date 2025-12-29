# Adamantine Wallet — Architecture Overview
Status: **draft v0.3**

This document provides a **high-level architectural map** of the Adamantine Wallet OS, covering its modules, core systems, security layers, data flows, and platform implementations.

It is intentionally descriptive rather than prescriptive: this file explains *how the city is laid out*, while deeper documents explain *how individual streets work*.

---

## 1. Architectural Goals

Adamantine Wallet is designed to be:

- **DigiByte-native** – first-class support for DGB, DigiAssets, and DigiDollar (DD).
- **Security-first** – deeply integrated with the 5-layer DigiByte Quantum Shield + Adaptive Core.
- **Policy-driven** – all sensitive actions governed by explicit decision, execution, and enforcement stages.
- **Multi-platform** – consistent UX and safety guarantees across **Android**, **iOS**, and **Web**.
- **Modular & auditable** – each concern (keys, assets, messaging, analytics) lives in its own module.
- **Future-proof** – ready for Enigmatic Layer-0 communication and post-quantum upgrades.

This file is the **“map of the city.”**
All other documents provide street-level detail.

---

## 2. High-Level Layering

From top (user) to bottom (chain), Adamantine is structured into these layers:

### **1. Client Apps (UI Layer)**

- `clients/android/`
- `clients/ios/`
- `clients/web/`

Responsible for:
- screens and navigation
- secure storage integration
- biometrics
- notifications
- UX response to Guardian decisions

Clients **never** implement security logic.  
They consume approved APIs exposed by the Wallet Core.

---

### **2. Wallet Core**

Handles:

- account abstraction
- key management
- UTXO selection
- transaction building
- fee calculation
- balance state for DGB, DigiAssets, and DigiDollar

This layer exposes a **stable API** shared across all clients and remains deterministic and testable.

---

### **3. Security & Guard Rails**

This layer enforces Adamantine’s core execution law:

**EQC decides → WSQK executes → Runtime enforces**

Includes:

- **EQC (Executive Quality Control)** – deterministic policy evaluation and verdict generation.
- **WSQK (Wallet Secure Quantum Kernel)** – hardened execution boundary for approved actions.
- **Runtime Orchestrator** – enforces sequencing, rate limits, and post-conditions.
- **Guardian Wallet** – local policy engine translating risk into user-facing decisions.
- **Shield Bridge** – integration layer connecting the wallet to DigiByte’s 5-layer Quantum Shield:
  - Sentinel AI v2
  - DQSN v2
  - ADN v2
  - QWG
  - Adaptive Core (DQAC)

Supports both:
- **online mode** (live shield signals)
- **offline mode** (cached risk profiles and local-only enforcement)

---

### **4. Assets & Value Layer**

- **DGB (base layer)** – standard UTXO asset.
- **DigiAssets** – tokens and NFTs; creation, issuance, transfers, burns.
- **DigiDollar (DD)** – mint/redeem logic, oracle connections, shield-aware risk checks.

Each asset type shares the same security pipeline and Guardian enforcement model.

---

### **5. Layer-0 Messaging (Enigmatic)**

Wallet-to-wallet communication through UTXO state planes:

- intents
- requests
- shield telemetry
- DD governance messages

Implemented under `modules/enigmatic-chat/`.

Messaging flows are optional and never required for core wallet operation.

---

### **6. Analytics & Telemetry**

Located in `modules/analytics-telemetry/`.

Collects **privacy-respecting, opt-in** signals such as:

- error patterns
- performance metrics
- aggregated shield event summaries

No personal data, addresses, or identifiers are collected.

---

### **7. Persistence & Configuration**

- secure storage (OS keychain / keystore)
- encrypted local databases
- `config/` directory for:
  - shield endpoints
  - node lists
  - risk profiles
  - guardian rules

All persisted data is designed to support offline operation.

---

### **8. External Dependencies**

- DigiByte full nodes (local or remote)
- Digi-Mobile (Android full node)
- Oracle services (for DigiDollar)
- Shield infrastructure endpoints (optional)

Adamantine remains functional even when some dependencies are unavailable.

---

## 3. Module Map

The repository is organised as:

- **`.github/`** – CI workflows, linting, docs validation.
- **`clients/`** – Android, iOS, and Web UI frontends.
- **`core/`**
  - `eqc/` – policy decision engine.
  - `wsqk/` – secure execution kernel.
  - `runtime/` – orchestration and enforcement.
  - `data-models/` – wallet state, contact, and message models.
  - `guardian-wallet/` / `guardian_wallet/` – guardian policies and runtime logic.
  - `pqc-containers/` – post-quantum key formats.
  - `qwg/` – Quantum Wallet Guard rules.
  - `risk-engine/` – scoring, thresholds, guardian integration.
  - `shield-bridge/` – interface to Shield layers.
  - `digiassets/` – asset parsing, mint, transfer, burn logic.
- **`modules/`**
  - `dd-minting/` / `dd_minting/` – DigiDollar mint/redeem flows.
  - `enigmatic-chat/` – Layer-0 messaging.
  - `analytics-telemetry/` – privacy-first analytics.
- **`docs/`** – architecture, design, narrative specifications.
- **`tests/`** – scenario-driven test plans for all modules.

Where both kebab-case and snake_case folders exist:
- **kebab-case** holds specifications or human-facing structure
- **snake_case** holds runtime Python implementations

---

## 4. Key Data Flows

### **4.1 DGB Send**

1. Client initiates send
2. Wallet Core selects UTXOs and drafts transaction
3. EQC evaluates policy context
4. Shield Bridge computes risk
5. Guardian applies policies
6. If allowed → WSQK executes signing
7. Runtime broadcasts
8. Optional telemetry logs anonymised events

---

### **4.2 DigiAsset Lifecycle**

1. User initiates create / issue / transfer
2. DigiAssets engine builds transaction pattern
3. EQC + Shield Bridge validate safety
4. Guardian enforces policy
5. Optional Enigmatic announcements embedded
6. Wallet signs and broadcasts

---

### **4.3 DigiDollar Mint / Redeem**

1. User selects mint or redeem
2. DD engine orchestrates oracle + shield checks
3. EQC produces verdict
4. Guardian policies apply
5. Safe → WSQK executes; unsafe → block or require guardian
6. Balances update accordingly

---

### **4.4 Enigmatic Messaging**

1. User creates message
2. Enigmatic encodes dialect pattern
3. Shield evaluates detectability and plausibility
4. EQC approves intent
5. Wallet signs
6. Receiver decodes via same dialect

---

## 5. Security & Trust Model

- **Device Trust** – keychains, secure enclave, encrypted databases.
- **Policy Enforcement** – EQC, WSQK, Runtime separation.
- **Shield Integration** – Sentinel, DQSN, ADN, QWG, Adaptive Core.
- **Guardian UX** – user experience shaped by real-time risk.
- **Opt-In Telemetry** – transparent and anonymous.

---

## 6. Platform Notes

### **Android & iOS**

- native biometric APIs
- secure storage primitives
- offline-capable with cached shield profiles

### **Web**

- hardened UX
- non-custodial
- optional browser-extension integration

---

## 7. Roadmap Hooks

- PQC signing container implementation
- DigiAsset gallery and marketplace
- advanced guardian schemes (travel mode, per-contact trust)
- additional Enigmatic dialects
- expanded shield heuristics
- multi-sig and social recovery

---

## 8. Digi-Mobile Integration (Android)

Adamantine can operate with multiple DigiByte node backends.
On Android, the preferred backend is a **local Digi-Mobile node** when available.

### **How it works**

1. Digi-Mobile runs a pruned DigiByte Core daemon on-device
2. Exposes JSON-RPC on `127.0.0.1:<port>`
3. Adamantine auto-detects the node and uses it for:
   - UTXO queries
   - fee estimation
   - mempool checks
   - broadcasting

If available, Adamantine switches into **local full-node mode**.

If unreachable, it falls back to remote nodes defined in `config/example-nodes.yml`.

### **Why it matters**

- trustless validation
- maximum privacy
- resistance to censorship and outages
- alignment with Guardian + Shield security model

With Digi-Mobile + Adamantine, Android becomes a **self-contained DigiByte security environment**.

---

*This document is updated as Adamantine evolves from design to implementation.*
