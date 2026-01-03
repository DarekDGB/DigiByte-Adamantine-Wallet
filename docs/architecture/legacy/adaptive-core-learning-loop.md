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

# Adaptive Core Learning Loop

This document explains how the Adaptive Core v2 improves protection over time
without taking control away from the user.

Key ideas:
- Learning is derived from observed outcomes and user decisions
- Updates improve detection, scoring, and UX
- Authorization always remains with the user and local policy

---

## Adaptive Core Learning Loop

Legend:
- Solid arrows = runtime events and outputs
- Dotted arrows = learning updates and knowledge propagation

```mermaid
graph TB
    %% =========================
    %% RUNTIME OBSERVATION
    %% =========================
    User([User]) --> UI["Guardian Wallet<br/>UI + Policy"]
    UI --> Gate["QWG<br/>Transaction Gate"]
    Gate --> Detect["Sentinel AI v2<br/>Local Detection"]
    Detect --> Gate
    Gate --> UI

    UI --> Decision{User Action}
    Decision -->|Approve| TxOK["Transaction Broadcast"]
    Decision -->|Reject| TxNo["Transaction Stopped / Edited"]

    %% =========================
    %% LEARNING INPUTS
    %% =========================
    TxOK --> Evidence["Outcome Evidence<br/>Success / Later Alerts<br/>External Signals"]
    TxNo --> Evidence
    Detect --> Signals["Detection Signals<br/>Patterns / Features<br/>Risk Factors"]
    UI --> Feedback["User Feedback<br/>Confirmation Events<br/>False Positive/Negative Flags"]

    Signals --> Learn["Adaptive Core v2<br/>Memory + Learning"]
    Evidence --> Learn
    Feedback --> Learn

    %% =========================
    %% LEARNING OUTPUTS (NON-CONTROLLING)
    %% =========================
    Learn -.Model/Rule Updates.-> Detect
    Learn -.Scoring Calibration.-> Gate
    Learn -.UX/Policy Suggestions.-> UI

    %% =========================
    %% OPTIONAL NETWORK PROPAGATION
    %% =========================
    subgraph Optional["OPTIONAL: DQSN v2 (Network Intelligence)"]
        DQSN["Aggregated Threat Context<br/>Cross-Node Correlation"]
    end

    Detect -.Anonymized Signals.-> DQSN
    DQSN -.Aggregated Context.-> Detect

    %% =========================
    %% STYLING (LIGHT, SAFE)
    %% =========================
    style Learn fill:#F4E8F8,stroke:#999
    style Optional fill:#E8F4F8,stroke:#999
```

---

## Safety Properties

- The Adaptive Core does not sign transactions.
- The Adaptive Core does not move funds.
- The Adaptive Core does not bypass user policy.
- Learning produces recommendations and updates only, not autonomous actions.

---

## Notes

This loop is designed to be testnet-friendly:
- instrumentable (logs, metrics, replay)
- reviewable (versioned rule/model updates)
- reversible (rollback to known-good profiles)
