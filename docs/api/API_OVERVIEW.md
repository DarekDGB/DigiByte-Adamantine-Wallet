# API Overview (Public Surface Lock)

**Author:** DarekDGB  
**License:** MIT

This folder defines the **public API surface** of Adamantine Wallet OS.

If something is documented in `docs/api/**`, it is treated as **public** unless explicitly marked internal.
Everything else in the repository is considered **internal** and may change without notice.

---

## Public vs Internal

### ✅ Public
Public APIs are the stable, supported interfaces intended for:
- Clients (Android / iOS / Web)
- Sync backends (providers)
- Integrations that build on the wallet engine

**Rule of thumb:**  
If a test relies on an interface as stable, or if a client/provider needs it, it is **public**.

### ❌ Internal
Anything not listed here (or explicitly marked internal) may change at any time:
- experiments
- prototypes
- implementation details
- future modules under active iteration

---

## Compatibility Promise (SemVer-ish)

We follow a simple compatibility promise for public APIs:

- **MAJOR** changes: breaking changes (rename, remove, change meaning)
- **MINOR** changes: additive, backward-compatible additions
- **PATCH** changes: bug fixes and clarifications

**Lock statement:**
- Public API: stable unless **MAJOR**
- Internal modules may change anytime

---

## Safety Guarantees

### No secrets stored
Public “state” objects store **only non-secret metadata**:
- network, indices, gap limit, etc.

**Never stored in WalletState:**
- seed
- mnemonic
- private keys
- xprv

Secrets remain in memory and are passed explicitly only where required.

---

## High-level flow (client → engine)

```
Client UI
  |
  v
WalletEngine (state + account + builders)
  |
  v
EQC (decides: ALLOW/DENY/STEP_UP)
  |
  v
WSQK (exec authority: scope + TTL + nonce)
  |
  v
Runtime (enforces invariants + executes)
```

---

## Files in this lock pack

- `WALLET_ENGINE_API.md` — what clients call
- `SYNC_API.md` — provider interface contract
- `TX_API.md` — build/sign/scripts/serialization boundaries
- `EQC_WSQK_API.md` — enforcement names + invariants
