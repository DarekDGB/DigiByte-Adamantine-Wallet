# Wallet Development Phases

This file tracks completed and planned wallet phases.

## Phase 1–3: Foundations (DONE)
- HD primitives
- secp256k1 (minimal, deterministic)
- Address encoding

## Phase 4: Wallet State & Accounts (DONE)
- WalletState (non-secret)
- WalletAccount model
- Receive / change chains

## Phase 5: UX Core (DONE)
- Receive address flow
- Index advancement rules
- Watch-only scaffolding

## Phase 6: Sync Engine (DONE)
- Provider interface
- Gap-limit discovery
- Balance + UTXO aggregation

## Phase 7: Transaction Builder (DONE)
- Unsigned tx builder
- Change handling
- Deterministic outputs

## Phase 8: Signing Boundary (DONE)
- Legacy SIGHASH_ALL
- P2PKH scriptSig
- Watch-only cannot sign

## Phase 9: End-to-End Send (DONE)
- Signed transaction container
- Raw tx serialization
- Broadcaster interface
- Full send flow test

---

## Phase 10 (NEXT — not started)
- Real network adapters (Electrum / HTTP)
- Mempool awareness
- Fee estimation providers
