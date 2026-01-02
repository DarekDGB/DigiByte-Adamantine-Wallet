# Wallet Engine API (Stable Client Interfaces)

**Author:** DarekDGB  
**License:** MIT

This document defines the stable interfaces that **clients** (Android/iOS/Web) can call.
The wallet engine is **local-first** and **does not perform network calls**.

- No threading/async assumptions.
- No network inside the wallet engine.
- Deterministic behavior for the same inputs.

---

## WalletState (non-secret)

Module: `core.wallet.state`

### Fields
- `network`: `"mainnet"` (testnet later)
- `coin_type`: `20` (DigiByte)
- `account`: `0` default
- `receive_index`: next external index (chain `/0`)
- `change_index`: next internal index (chain `/1`)
- `gap_limit`: discovery gap limit (default `20`)

### Invariants
- indices are `>= 0`
- gap_limit is `> 0`
- **no secrets** in state

### Constructors / serialization
- `WalletState.default()` (if present) + sensible defaults
- `WalletState.to_json()` / `WalletState.from_json()` round-trip

---

## WalletAccount (private-capable account)

Module: `core.wallet.account`

Represents a BIP44 account view over an HD root that contains private key material.

### Address methods
- `get_receive_address(state)`  
  Returns current receive address **without advancing**.
- `next_receive_address(state)`  
  Advances receive index and returns the new receive address.
- `receive_address_at(i)`  
  Deterministic receive address for index `i`.
- `change_address_at(i)`  
  Deterministic change address for index `i`.

### Notes
- Derivation is deterministic for the same seed/root and path.
- Signing capabilities exist only when private key material exists.

---

## PublicWalletAccount (watch-only account)

Module: `core.wallet.public_account`

Represents a BIP44 account view over an HD root that contains **public key only** material.

### Address methods (same shape)
- `get_receive_address(state)`
- `next_receive_address(state)`
- `receive_address_at(i)`
- `change_address_at(i)`

### Explicit boundary: cannot sign
A PublicWalletAccount **must never** be able to sign.
Any attempt to sign using watch-only objects must raise a deterministic error.

---

## Design Boundary Summary

- Clients call wallet engine functions.
- Wallet engine never does network calls.
- Sync and broadcast happen via **provider interfaces**, not inside the engine.
- Signing is a separate boundary and must be policy-gated (EQC/WSQK) as the system matures.
