# Contributing to DigiByte Adamantine Wallet OS

**Adamantine Wallet OS** is not a traditional wallet.  
It is a **full DigiByte Wallet Operating System**, architected as a modular, multi-client, multi-layer system integrating:

- DigiAssets v3  
- DigiDollar minting  
- Q-ID (PQC identity)  
- Enigmatic Layer-0 messenger  
- Guardian Wallet (user-protection layer)  
- Quantum Wallet Guard (QWG)  
- **EQC (Equilibrium Confirmation)** — deterministic decision layer  
- **WSQK (Wallet-Scoped Quantum Key)** — scoped execution authority  
- Shield Bridge (Sentinel, DQSN, ADN, Adaptive Core)  
- Node & DigiMobile integration  
- iOS, Android, and Web client code  
- Wallet engine, UTXO logic, parsing, builders, risk engine  

This repository contains **core security and architecture** for DigiByte’s long-term upgrade path.  
Because of this, **contributions must be extremely disciplined**.

Adamantine enforces a non-negotiable invariant:

> **EQC decides. WSQK executes. Runtime enforces.**

Any contribution that weakens, bypasses, or obscures this invariant will be rejected.

---

## ✅ What Contributions ARE Welcome

### ✔️ 1. Client Improvements (Android / iOS / Web)
- UI documentation and UX improvements  
- Safer send/receive flows  
- Performance optimizations  
- Non-breaking architectural enhancements  

### ✔️ 2. Wallet Engine & UTXO Logic
- Improvements to wallet state, balance tracking, and UTXO management  
- Safer transaction builders  
- Fee estimation refinements  
- Expanded test coverage  

### ✔️ 3. DigiAssets v3 & DigiDollar
- Parser enhancements  
- Metadata validation  
- Safe minting logic  
- Deterministic state management  

### ✔️ 4. Shield Integration
- Shield bridge extensions  
- Node-health interpretation improvements  
- Runtime guard hardening  
- Risk-response routing  

### ✔️ 5. Guardian Wallet, QWG, EQC & WSQK Bridges
- Clearer user-facing warnings  
- Improved rule mappings  
- UX-safe escalation logic  
- Explicit preservation of EQC/WSQK execution flow  

### ✔️ 6. Documentation
- Architecture diagrams  
- Step-by-step flow explanations  
- Module responsibility clarification  
- Test examples  

### ✔️ 7. Test Suite Expansion
- Wallet engine tests  
- Node manager simulations  
- DigiAssets edge cases  
- Shield and signing-gate integration tests  
- Regression prevention  

---

## ❌ What Will NOT Be Accepted

### 🚫 1. Core Architecture Changes
The repository structure is **non-negotiable**:

```
clients/
core/
modules/
docs/
config/
tests/
```

No flattening, merging, or repurposing without architectural approval.

### 🚫 2. Mixing Responsibilities
Forbidden examples include:
- UI logic inside the wallet engine  
- Shield, EQC, or WSQK logic inside client code  
- Guardian/QWG logic embedded in network modules  
- DigiAssets parsing outside its designated module  

### 🚫 3. EQC / WSQK Bypass or Weakening
Any code path that:
- signs without EQC approval  
- executes without WSQK authority  
- shortcuts runtime enforcement  

will be rejected immediately.

### 🚫 4. Consensus or Node Rule Changes
Adamantine:
- does **NOT** modify consensus  
- does **NOT** validate blocks  
- does **NOT** alter node rules  

### 🚫 5. Black-Box AI
All logic must be deterministic and auditable.  
No opaque ML or neural networks.

### 🚫 6. Breaking Cross-Client Parity
Android, iOS, and Web must behave identically.

### 🚫 7. Removing Safety Layers
Guardian Wallet, QWG, EQC, WSQK, Shield Bridge, Risk Engine, and Node Health logic are mandatory.

---

## 🧱 Design Principles

1. **Security First** — user protection is the default  
2. **Modularity** — every function belongs in the correct layer  
3. **Cross-Client Consistency** — identical behavior across platforms  
4. **Explainability** — every decision must be auditable  
5. **Determinism** — same inputs → same outputs  
6. **Upgrade-Safe Design** — PQC, DigiAssets v3, DigiDollar ready  
7. **Interoperability** — integrates cleanly with Shield & Guardian systems  

---

## 🚀 Getting Started

### First Time Contributors
1. Read `docs/RUNTIME_INVARIANTS.md`  
2. Read `docs/api/API_OVERVIEW.md`  
3. Pick an issue labeled **good first issue**  
4. Run `pytest` locally and ensure CI passes  
5. Create a feature branch  
6. Submit a PR with tests  

### New to EQC / WSQK
- Start with `docs/EQC_WSQK_API.md`  
- Review `tests/test_shield_signing_gate.py`  
- Understand the invariant **before writing code**  

### Building a Client
- Reference `docs/WALLET_ENGINE_API.md`  
- Never import from `core/shield/*`, `core/eqc/*`, or `core/wsqk/*` directly  
- Only call execution through approved intent APIs  
- Test against watch-only mode first  

---

## 🔄 Code Review & Approval Process

1. **Automated checks (required)**
   - CI green on all platforms  
   - Test coverage maintained  
   - Deterministic behavior preserved  

2. **Architectural review** (**@DarekDGB**)
   - EQC/WSQK invariants intact  
   - No responsibility mixing  
   - Deterministic and auditable  

3. **Merge**
   - Approval + CI green required  
   - Squash or rebase (clean history)  

---

## 🧪 Testing Expectations

- New features require tests  
- Test coverage must not decrease  
- End-to-end wallet flows must remain green  
- Signing, state, or EQC changes must include invariant tests  

CI must stay green.

---

## 📝 License

By contributing, you agree your work is licensed under the MIT License.

© 2026 **DarekDGB**
