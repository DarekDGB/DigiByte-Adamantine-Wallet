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

# Wallet-Only Minimal Flow

This document shows the **minimal protection path** when Adamantine is used
without any optional network intelligence or external services.

Key ideas:
- Fully local operation
- No dependency on DQSN or network connectivity
- User remains the final authority at all times

---

## Wallet-Only Minimal Flow

Legend:
- Solid arrows = local runtime path
- No dotted arrows (no network interaction)

```mermaid
graph TB
    User([User]) --> UI

    subgraph Device["ON-DEVICE ONLY (Offline-Capable)"]
        UI["Guardian Wallet<br/>UI + Policy"]
        Gate["QWG<br/>Transaction Gate"]
        Detect["Sentinel AI v2<br/>Local Detection"]
        Learn["Adaptive Core v2<br/>Local Memory"]
    end

    UI -->|Intent| Gate
    Gate -->|Signals| Detect
    Detect -->|Assessment| Gate
    Gate -->|Risk Summary| UI

    UI --> Decision{Authorize?}
    Decision -->|Approve| Broadcast["Prepare Transaction"]
    Decision -->|Reject| Stop["Stop / Edit Transaction"]

    Broadcast --> Learn
    Stop --> Learn

    Learn -.Updates.-> Detect
    Learn -.Suggestions.-> UI
```

---

## Properties

- Works fully offline
- No data leaves the device
- No network intelligence required
- No loss of protection features

---

## Notes

This flow represents the safest baseline configuration and
is suitable for cold environments, air-gapped review,
and high-sovereignty users.
