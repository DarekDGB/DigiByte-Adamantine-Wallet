# Wallet Development Roadmap — Adamantine Wallet OS

This document defines the **approved build order** for wallet features.
It exists to prevent scope creep and architectural drift.

---

## Current State (Completed)

✅ BIP39 mnemonic + seed  
✅ BIP32 master + hardened derivation  
✅ BIP32 non-hardened derivation  
✅ BIP44 account / chain / address structure  
✅ CI coverage across platforms  

---

## Phase 4 — Address Encoding (Next)

Goal: User-visible wallet output.

Planned:
- HASH160 (already available)
- Base58Check encoder
- DigiByte P2PKH prefixes
- Address validation

Not included yet:
- Bech32
- P2SH
- Multi-sig

---

## Phase 5 — Wallet Account Logic

- External / internal chain tracking
- Address index management
- Gap limit handling
- Deterministic account discovery

---

## Phase 6 — Transactions (Later)

- Raw transaction builder
- Fee calculation
- Signing (single-sig only)
- Broadcast hooks (client-side)

---

## Phase 7 — Assets & Extensions

- DigiAssets
- DigiDollar
- Metadata layers
- Advanced scripting

---

## Rule of Progression

Each phase must:
- Pass CI
- Be documented
- Expose a minimal public API
- Avoid breaking lower layers

No skipping phases.

---

## Guiding Principle

**Correct > Fast > Fancy**

Security and determinism always come first.
