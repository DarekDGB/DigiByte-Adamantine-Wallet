# Discovery Contract (Gap Limit) — Adamantine Wallet OS

This document defines how address discovery will be plugged into Adamantine Wallet OS.

## Goal

Support BIP44-style discovery:

- scan addresses in order
- stop after `gap_limit` consecutive unused addresses

This allows wallets to restore accounts deterministically without knowing the last index in advance.

## Provider Interface

`AddressDiscoveryProvider` must implement:

- `is_used(address: str) -> bool`

A provider answers: “Has this address ever been used on-chain?”

Examples of provider implementations (later):
- ElectrumX / Esplora / full node indexer
- Mobile light-client sync engine
- Local cache + periodic refresh

## Core Helper

`discover_used_indices(...)` performs deterministic scanning given:
- a provider
- an address function `address_at_index(i) -> str`
- `gap_limit`
- start index

No networking exists in this module.
It is only logic + contract.

## Integration

WalletAccount supplies:
- `receive_address_at(i)`
- `change_address_at(i)`

A sync engine will:
- run discovery on receive chain
- run discovery on change chain
- update WalletState indices accordingly
