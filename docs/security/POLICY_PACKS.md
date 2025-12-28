# EQC Policy Packs

Policy packs are optional, named rule-sets that can be enabled at runtime to **tighten security** for specific deployments.

They exist so future contributors can add stricter constraints **without changing the base EQC policy**.

Author: DarekDGB  
License: MIT (see root LICENSE)

---

## What a policy pack can do

A policy pack can:

- **DENY** certain actions in stricter environments
- **Require STEP_UP** (extra confirmation) for certain risk conditions

A policy pack should **not loosen security**.

---

## How packs are enabled

Policy packs are enabled via an environment variable:

- `EQC_POLICY_PACKS=PACK_A,PACK_B,PACK_C`

The engine reads the list and evaluates those packs (if registered).

---

## Example pack included

This repo includes a scaffold example:

- `HIGH_VALUE_STEP_UP`

It demonstrates a deployment rule:

- For `send` actions above a threshold → require **STEP_UP**

This is intentionally simple and meant as a template.

---

## Security rule: packs only tighten

The intended invariant is:

> Enabling any pack must never turn a DENY or STEP_UP into ALLOW.

Step 5.2 adds tests that enforce this invariant.
