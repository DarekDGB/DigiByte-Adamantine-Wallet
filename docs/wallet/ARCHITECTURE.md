# Core Wallet Architecture

This document explains the **high-level flow** of the wallet core.

## Data Flow

Seed
 → HDNode (root)
 → WalletAccount
 → Address chains (receive / change)
 → Discovery (provider)
 → UTXOs
 → UnsignedTransaction
 → Signing boundary
 → SignedTransaction
 → Raw hex
 → Broadcaster

## Key Boundaries
- **WalletState**: UX state only, no secrets
- **WalletAccount**: deterministic derivation logic
- **Signing**: requires private keys, enforced by tests
- **Public / watch-only**: derive addresses, never sign
- **Broadcast**: abstracted, replaceable

## Why this matters
- Each layer is testable in isolation
- Security boundaries are explicit
- Network logic can change without touching crypto
- Perfect base for mobile-first development
