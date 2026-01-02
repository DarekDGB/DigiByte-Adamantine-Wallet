# Transaction API (Build / Sign / Scripts / Serialization)

**Author:** DarekDGB  
**License:** MIT

This document locks the transaction flow boundaries for the wallet engine.

---

## Build (Unsigned)

Stable function:
- `build_unsigned_tx(...) -> UnsignedTransaction`

Expectation:
- builder is deterministic for given inputs
- builder does not broadcast
- builder does not sign unless explicitly called to do so (separate boundary)

UnsignedTransaction includes:
- inputs (prevouts + values as required by your builder model)
- outputs (address + value_sats, or script_pubkey + value_sats depending on model)
- fee_sats

---

## Sign (Boundary)

Signing functions are a strict boundary.

Rules:
- signing accepts **private keys explicitly**
- signing **must fail** for watch-only accounts
- signing must raise a deterministic `SigningError` (or equivalent)

This project will later enforce:
- **no signing unless EQC verdict is ALLOW**
- WSQK authority scoping (TTL + nonce) before execution

---

## Scripts

Stable primitives:
- `legacy_sighash_all(...)`
- `build_p2pkh_scriptsig(...)`

Determinism:
- sighash must be deterministic for the same unsigned tx, input index, and pubkey
- scriptsig building must be deterministic for the same inputs

---

## Serialization

Stable output:
- raw transaction bytes (or hex encoding) suitable for broadcast

Example statement:
- âSerialization output is rawtx hex bytes.â

Broadcast is external:
- wallet engine returns serialized bytes/hex
- providers / clients broadcast using their backend transport

---

## What is deterministic vs policy-gated

Deterministic:
- tx building (given same inputs)
- sighash
- scriptsig structure
- serialization

Policy-gated (as the system hardens):
- signing (must be behind EQC/WSQK and runtime enforcement)
