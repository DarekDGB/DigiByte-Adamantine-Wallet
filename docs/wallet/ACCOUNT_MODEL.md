# Wallet Account Model — Adamantine Wallet OS

**Status:** Stable (v1)
**Layer:** Wallet logic (above HD core, below networking)

---

## Overview

The `WalletAccount` abstraction represents a single BIP44 account inside
Adamantine Wallet OS.

It is responsible for:
- Deterministic address derivation
- External / internal chain separation
- Address index tracking

It is **not** responsible for blockchain state, UTXO scanning, or persistence.

---

## BIP44 Structure

Each account follows the standard BIP44 hierarchy:

```
m / 44' / coin_type' / account' / change / index
```

Where:
- `coin_type` — DigiByte uses SLIP-0044 value **20**
- `account` — logical account number (default: 0)
- `change`:
  - `0` = external / receive addresses
  - `1` = internal / change addresses
- `index` — address index (0, 1, 2, …)

---

## External vs Internal Chains

### External Chain (`change = 0`)
- Used for receiving funds
- Public-facing addresses
- Incremented via `next_receive_address()`

### Internal Chain (`change = 1`)
- Used for change outputs
- Not shown to users
- Incremented via `next_change_address()`

The two chains are tracked **independently**.

---

## Index Tracking Rules

Each `WalletAccount` tracks:

- `receive_index`
- `change_index`

Rules:
- Indices always increment by +1
- Indices never decrease
- No address reuse at the account level

Persistence is handled outside this layer.

---

## Public API

Minimal public surface:

- `receive_address_at(index)`
- `change_address_at(index)`
- `next_receive_address()`
- `next_change_address()`

These methods always return deterministic DigiByte P2PKH addresses.

---

## Gap Limit

Each account has a configurable `gap_limit` (default: 20).

At this stage:
- The gap limit is stored
- Validation is enforced (`gap_limit > 0`)
- Discovery logic is **not implemented yet**

Future scanning modules will use this value.

---

## Security Model

- Private keys remain inside HD derivation + bridge layers
- Account layer never serializes keys
- No signing logic exists here
- Deterministic output for identical inputs

---

## Explicit Non-Goals

This layer does **not**:
- Track UTXOs
- Scan the blockchain
- Persist state to disk
- Build or sign transactions
- Manage multiple accounts

These belong to higher layers.

---

## Design Principles

- Deterministic
- Minimal
- Auditable
- Hard to misuse

If functionality is missing here, it is intentional.

---

## Versioning

Breaking changes require:
- Updated tests
- Updated documentation
- Explicit version bump
