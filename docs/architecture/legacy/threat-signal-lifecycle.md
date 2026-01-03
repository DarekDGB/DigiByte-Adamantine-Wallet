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

# Threat Signal Lifecycle

This document describes how threat signals are created, processed, shared,
and expired within the Adamantine protection architecture.

Key ideas:
- Signals are derived from behavior, not identities
- Signals are anonymized before any sharing
- Signals have a limited lifetime and are not permanently stored
- Users are never tracked or deanonymized

---

## Threat Signal Lifecycle

Legend:
- Solid arrows = local processing
- Dotted arrows = optional network sharing
- Dashed boxes = transient data (time-limited)

```mermaid
graph TB
    %% =========================
    %% SIGNAL CREATION (LOCAL)
    %% =========================
    Event["Suspicious Event<br/>Anomaly / Pattern Match"] --> Extract

    Extract["Signal Extraction<br/>Features + Context"] --> Normalize

    Normalize["Normalization<br/>Remove Identifiers<br/>Hash / Bucketize"] --> LocalSignal

    LocalSignal["Local Threat Signal<br/>(Ephemeral)"] --> Score

    Score["Risk Scoring<br/>Local Context"] --> Action

    Action["Local Action<br/>Warn / Challenge / Block"]

    %% =========================
    %% LOCAL LEARNING
    %% =========================
    LocalSignal --> Learn["Adaptive Core v2<br/>Local Memory"]
    Action --> Learn

    %% =========================
    %% OPTIONAL NETWORK SHARING
    %% =========================
    subgraph Optional["OPTIONAL: DQSN v2 (Network Intelligence)"]
        Aggregate["Aggregation<br/>Cross-Node Correlation"]
        Decay["Signal Decay<br/>TTL / Expiration"]
    end

    LocalSignal -.Anonymized Signal.-> Aggregate
    Aggregate --> Decay
    Decay -.Aggregated Context.-> Score

    %% =========================
    %% EXPIRATION
    %% =========================
    Decay --> Expire["Signal Expired<br/>No Long-Term Storage"]

    %% =========================
    %% STYLING
    %% =========================
    style LocalSignal fill:#E8F4F8,stroke:#999
    style Learn fill:#F4E8F8,stroke:#999
    style Optional fill:#E8F4F8,stroke:#999
    style Expire fill:#EEEEEE,stroke:#999
```

---

## Privacy Properties

- No wallet addresses are shared.
- No private keys are accessed.
- No persistent user identifiers are transmitted.
- Signals are aggregated and decayed over time.

---

## Notes

Threat signals exist to improve protection, not to monitor users.
All sharing is optional and non-blocking.
