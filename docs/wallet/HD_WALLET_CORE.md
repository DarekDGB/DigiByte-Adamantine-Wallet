# HD Wallet Core — Adamantine Wallet OS

**Status:** Stable (v1 core)  
**Scope:** Deterministic key derivation only  
**Security level:** High (private-key only, no serialization yet)

---

## Overview

The Adamantine Wallet HD Core implements a strict, spec-correct
deterministic wallet foundation based on:

- BIP39 — Mnemonic → Seed
- BIP32 — Hierarchical Deterministic keys
- BIP44 — Standard wallet structure

This module is intentionally minimal and conservative.
It focuses on correctness, determinism, and auditability.

No networking, no address encoding, no serialization is included here.

---

## Implemented Standards

### BIP39
- English wordlist (2048 words)
- Checksum validation
- Mnemonic → seed derivation

### BIP32
- Master key derivation from seed
- Hardened child derivation (CKDpriv)
- Non-hardened child derivation (CKDpriv)
- secp256k1 curve arithmetic
- Parent fingerprint calculation (HASH160)

### BIP44
Supported structure:

```
m / 44' / coin_type' / account' / change / address_index
```

- Purpose: hardened
- Coin type: hardened
- Account: hardened
- Change: non-hardened (0 = external, 1 = internal)
- Address index: non-hardened

---

## Public API (Stable Contract)

### Core Types
- HDNode
- DerivationPath
- DerivationIndex

### Key Functions
- HDNode.from_seed(seed)
- HDNode.derive_hardened(index)
- HDNode.derive_nonhardened(index)
- HDNode.derive_path(path)

### BIP44 Helpers
- derive_bip44_purpose(root)
- derive_bip44_coin(root, coin_type)
- derive_bip44_account(root, coin_type, account)
- derive_bip44_chain(account_node, change)
- derive_bip44_address(account_node, change, index)

### Path Builders
- bip44_path(coin_type, account, change, address_index)
- bip44_account_path(coin_type, account)

---

## Explicit Non-Goals (By Design)

The following are **not implemented** in this core:

- xpub / xprv serialization
- Base58Check encoding
- Bech32 encoding
- Address generation
- Networking / node communication
- UTXO management
- Transaction building
- Signing

These belong to higher layers.

---

## Security Model

- Private keys never leave the HD core
- No global state
- Deterministic output for identical inputs
- All derivations covered by CI tests
- Hardened derivation used for all critical boundaries

---

## Design Philosophy

This module is designed to be:

- Auditable
- Deterministic
- Minimal
- Hard to misuse

If something is not explicitly implemented here, it is intentional.

---

## Versioning

Breaking changes to this module require:
- Test updates
- Documentation updates
- Explicit version bump
