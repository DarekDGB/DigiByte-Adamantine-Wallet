# EQC Policy Packs

Policy packs are optional, named rule-sets that can be enabled at runtime to **tighten security**
for specific deployments.

They exist so future contributors and operators can introduce stricter constraints **without
modifying the base EQC policy or core engine logic**.

Author: DarekDGB  
License: MIT (see root LICENSE)

---

## What a policy pack can do

A policy pack may:

- **DENY** certain actions in stricter environments
- **Require STEP_UP** (additional confirmation) for higher-risk situations

A policy pack **must never loosen security**.

---

## What a policy pack must NOT do

A policy pack must **never**:

- Turn a **DENY** into **ALLOW**
- Turn a **STEP_UP** into **ALLOW**
- Override hard engine invariants (browser / extension blocks, DigiDollar rules, etc.)

Policy packs are strictly *additive constraints*.

---

## How policy packs are enabled

Policy packs are enabled via an environment variable:

```bash
EQC_POLICY_PACKS="module.path:PackClass,module.path:AnotherPack"
```

Example:

```bash
EQC_POLICY_PACKS="core.eqc.policies.packs.high_value_step_up:HighValueStepUpPack"
```

If the variable is unset or empty, **no packs are applied** and EQC runs with base policy only.

---

## Evaluation order

When enabled, EQC evaluates policies in this order:

1. **Hard engine invariants** (non-negotiable)
2. **Device & transaction classifiers**
3. **Base EQC policy**
4. **Enabled policy packs**
5. **Deterministic verdict merge**

Final verdict priority:

```
DENY > STEP_UP > ALLOW
```

---

## Example policy pack included

This repository includes a scaffold example:

- `HIGH_VALUE_STEP_UP`

Behavior:

- Applies only to `send` actions
- If `amount >= threshold` â require **STEP_UP**
- Otherwise â no change

This pack demonstrates how deployments can enforce additional safeguards
without touching the base policy.

---

## Security invariant: packs only tighten

The enforced invariant is:

> Enabling any policy pack must never reduce security.

Formally:

- `DENY` may stay `DENY`
- `ALLOW` may become `STEP_UP` or `DENY`
- `STEP_UP` may become `DENY`
- **No path may become less restrictive**

This invariant is enforced by automated tests.

---

## Intended audience

Policy packs are intended for:

- Operators running hardened environments
- Enterprises with stricter compliance requirements
- Future contributors extending security rules safely

They are **not** required for normal wallet operation.
