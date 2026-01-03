<!--
LEGACY DOCUMENT NOTICE

This document reflects an earlier conceptual design stage of Adamantine Wallet OS.
It is preserved for historical context.

It is NOT authoritative for current signing, execution, storage, or security behavior.
For the locked architecture, see:
- docs/ARCHITECTURE_LOCK.md
- docs/architecture/DIAGRAMS_INDEX.md
- docs/architecture/signing-gate-flow.md
- docs/architecture/storage-architecture.md
- docs/architecture/dd-storage-model.md
-->

# Policy Engine Flow

This document explains how user-defined policies are evaluated during
transaction preparation and authorization in the Adamantine Wallet.

Key ideas:
- Policies are evaluated locally
- Users remain in control of final authorization
- Policies constrain behavior, they do not automate spending

---

## Policy Engine Flow

Legend:
- Solid arrows = runtime evaluation path
- Decision nodes = explicit user or policy gates

```mermaid
graph TB
    User([User]) --> UI["Guardian Wallet<br/>UI + Policy Editor"]

    UI --> Intent["Transaction Intent<br/>Amount / Recipient / Asset"]

    Intent --> PolicyLoad["Load Active Policies<br/>User + Defaults"]

    PolicyLoad --> Context["Context Assembly<br/>Device / Time / History"]

    Context --> Evaluate["Policy Evaluation Engine"]

    Evaluate -->|Allow| Gate["QWG<br/>Transaction Gate"]
    Evaluate -->|Require Confirmation| Confirm["User Confirmation Required"]
    Evaluate -->|Deny| Deny["Policy Denial<br/>Block Action"]

    Confirm --> UI
    Deny --> UI

    Gate --> Detect["Sentinel AI v2<br/>Risk Assessment"]
    Detect --> Gate

    Gate --> Decision{Authorize?}
    Decision -->|Approve| Broadcast["Prepare / Broadcast Transaction"]
    Decision -->|Reject| Stop["Stop / Edit Transaction"]

    %% =========================
    %% FEEDBACK
    %% =========================
    Broadcast --> Learn["Adaptive Core v2<br/>Policy Feedback"]
    Stop --> Learn

    Learn -.Suggestions.-> UI
```

---

## Policy Types

- Spend limits (amount, frequency)
- Destination allowlists / blocklists
- Time-based restrictions
- Asset-specific rules
- Confirmation thresholds

---

## Safety Properties

- Policies never sign transactions
- Policies cannot bypass user confirmation
- All enforcement happens on-device

---

## Notes

The policy engine exists to reduce user error and risk exposure,
not to automate financial decisions.
