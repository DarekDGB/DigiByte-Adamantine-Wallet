# Sync API (Provider Contract Lock)

**Author:** DarekDGB  
**License:** MIT

This document freezes the **provider interface** that allows anyone to plug in a backend later.
The wallet engine remains network-free; providers implement network I/O externally.

---

## Core Types

### UTXO
Module: `core.wallet.sync` (or equivalent)

Fields:
- `txid: str` (hex)
- `vout: int`
- `value_sats: int`
- `address: str`

### SyncResult
Module: `core.wallet.sync` (or equivalent)

Fields (minimum):
- `balance_sats: int`
- `utxos: list[UTXO]`
- `receive_last_used: int | None`
- `change_last_used: int | None`
- `scanned_receive: int`
- `scanned_change: int`

---

## SyncProvider Contract (stable)

A provider must implement:

- `is_used(address: str) -> bool`  
  Returns whether an address has been used (has any history).

- `list_utxos(address: str) -> list[UTXO]`  
  Returns spendable UTXOs for that address.

---

## sync_account()

Stable function:
- `sync_account(provider, account, state, max_scan=...) -> SyncResult`

Expectations:
- discovery respects `state.gap_limit`
- scanning stops at `max_scan` safety bound
- result includes scanned counts + last-used indices (or None)

---

## Fake provider example

```python
from core.wallet.sync import UTXO, sync_account

class FakeSyncProvider:
    def __init__(self, used: set[str], utxos_by_addr: dict[str, list[UTXO]]) -> None:
        self._used = used
        self._utxos = utxos_by_addr

    def is_used(self, address: str) -> bool:
        return address in self._used

    def list_utxos(self, address: str) -> list[UTXO]:
        return list(self._utxos.get(address, []))
```

This mirrors the test approach and keeps behavior deterministic.
