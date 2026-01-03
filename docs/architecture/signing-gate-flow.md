# Signing Gate Flow — EQC → Shield → WSQK → Runtime

**Author:** DarekDGB  
**License:** MIT

This diagram is **authoritative** for all sensitive execution (signing/minting/authorization).
There is **one supported entrypoint**:

- `execute_signing_intent(...)` in `core/runtime/shield_signing_gate.py`

Any path that bypasses this gate is **invalid by architecture**.

---

## High-Level Flow (Locked)

```mermaid
flowchart TD
  A[SigningIntent<br/>(wallet_id, account_id, action, asset, ...)] --> B{Watch-only?}
  B -- Yes --> X[BLOCK<br/>ExecutionBlocked<br/>"watch-only account"]
  B -- No --> C[EQC Engine<br/>decide(context)]
  C --> D{EQC Verdict == ALLOW?}
  D -- No --> Y[BLOCK<br/>ExecutionBlocked<br/>"EQC blocked"]
  D -- Yes --> E[Shield Evaluator<br/>evaluate(intent)]
  E --> F{Shield blocked?}
  F -- Yes --> Z[BLOCK<br/>ExecutionBlocked<br/>"Shield blocked"]
  F -- No --> G[WSQK Bind Scope<br/>bind_scope_from_eqc(...)]
  G --> H[Runtime Capability<br/>issue_runtime_capability(...)]
  H --> I[Execute With Scope<br/>execute_with_scope(...)]
  I --> J[Result<br/>signed tx / execution output]
```

---

## Invariants (Non-Negotiable)

1. **Watch-only block is first**
   - If the account is watch-only, execution is blocked **before** EQC, Shield, or WSQK.

2. **EQC is decision-only**
   - EQC may compute context hashes and produce verdicts.
   - EQC must not sign, mint, or execute.

3. **Shield is a second gate**
   - Shield can block even if EQC allows.

4. **WSQK executes, it does not decide**
   - WSQK receives a scope bound from EQC decision + intent context.
   - WSQK execution is time-bounded (TTL) and scope-bounded.

5. **Runtime enforces**
   - Execution requires a valid runtime capability bound to the scope hash.
   - No direct signing is supported.

---

## Code References

- Gate entrypoint: `core/runtime/shield_signing_gate.py`
- EQC context builder: `_build_eqc_context(...)`
- WSQK binding: `core/wsqk/context_bind.py`
- WSQK executor: `core/wsqk/executor.py`
- Runtime capability: `core/runtime/capabilities.py`
