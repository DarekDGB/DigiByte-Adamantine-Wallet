# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AdamantineOS,
please report it **responsibly and privately**.

 **Security Contact Email:**
adamantinewalletos@gmail.com

---

## Scope

This security policy applies to:

- Core execution contracts
- Enforcement logic (EQC, WSQK, TVA)
- Adapter validation boundaries
- Deterministic policy handling
- Shield v4 receipt, component-signature, trust-registry, and policy verification
- Freshness, replay/denylist, durable audit acknowledgement, and bounded-work enforcement

## Shield v4 candidate boundaries

AdamantineOS remains verify-only for Shield evidence and the final execution
boundary. Shield evidence is not final approval and cannot sign transactions,
broadcast, or change DigiByte consensus. A wallet consumes only AdamantineOS
final output. The compatibility default remains `shield_v4_required=False`;
v4-required policy must be explicitly selected by trusted integration code.

The current unreleased verifier candidate is documented in the
[final proof pack](docs/PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md)
and [release-status record](docs/ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md).
F deliberately retains package version `3.0.0` without a release stamp.
The six-node native proof uses live ML-DSA-65 and draft Falcon-1024 with
TEST-ONLY classical callbacks; it proves neither a production Ed25519 provider
nor HSM, FIPS-validated deployment, or final FIPS 206 compliance.

Deployments supply trusted key/replay state, raw transport limits, a real
durable append-only audit sink, and final-policy-gated wallet integration.
An in-memory test acknowledgement is not proof of storage durability.
Deterministic performance callbacks do not measure native PQC latency.

---

## Out of Scope

The following are **not considered security vulnerabilities**:

- Missing features
- Design disagreements
- Performance optimizations
- User interface behavior
- Third-party integrations not maintained here

---

## Disclosure Guidelines

Please include:
- A clear description of the issue
- Steps to reproduce (if applicable)
- Impact assessment
- Any suggested mitigations

Do **not** open public GitHub issues for security-sensitive findings.

---

## Response Commitment

Valid reports will receive:
- Acknowledgement within a reasonable timeframe
- Investigation and assessment
- Coordinated disclosure if applicable

---

## Philosophy

Security in AdamantineOS is based on:
- Explicit authority
- Deterministic behavior
- Fail-closed execution
- Auditable design

Thank you for helping keep the project secure.
