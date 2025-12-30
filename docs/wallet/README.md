# DigiByte Adamantine Wallet OS — Core Wallet v1

This document describes the **current, completed scope** of the Core Wallet (v1).
Everything here is **implemented, tested, and CI-green**.

## What is included (DONE)
- Deterministic wallet core (BIP32 / BIP44 — DigiByte coin type 20)
- HD key derivation (private & watch-only public paths)
- Address derivation (Legacy P2PKH, D-addresses)
- Wallet state & persistence (non-secret JSON state)
- Account model (receive / change chains)
- Gap-limit discovery scaffold (provider-driven)
- UTXO sync engine (provider interface)
- Unsigned transaction builder
- Legacy SIGHASH_ALL (deterministic)
- P2PKH scriptSig builder
- Transaction signing boundary (watch-only cannot sign)
- Raw transaction serialization
- Broadcaster interface + FakeBroadcaster
- End-to-end send flow test (UTXO → rawtx → broadcast)

## What is intentionally NOT included (YET)
- Real network connections (Electrum / Insight / REST)
- Mempool logic, RBF, CPFP
- SegWit, P2SH, Bech32
- Full script interpreter or validation engine
- Fee estimation from network
- UI / UX layers

## Design rules
- **CI must stay green**
- **No secrets in WalletState**
- **Watch-only safety is enforced**
- **Boundaries are explicit and test-proven**
- **iPhone-friendly development**

This Core Wallet v1 is a **stable foundation**.
Future phases extend it without breaking this contract.
