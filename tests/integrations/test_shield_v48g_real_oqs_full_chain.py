from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

import pytest

if os.environ.get("SHIELD_V4_REAL_OQS") != "1":
    pytest.skip("set SHIELD_V4_REAL_OQS=1 to run the real liboqs ML-DSA full-chain proof", allow_module_level=True)

try:
    oqs = pytest.importorskip("oqs")
except SystemExit as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)
except Exception as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)

from adamantine.v1.contracts.reason_ids import ReasonId  # noqa: E402
from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (  # noqa: E402
    COMPONENT_ROLES,
    DEFAULT_STANDARD_PROFILE_BY_ALGORITHM,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    receipt_hash,
    signed_payload_hash,
    unsigned_receipt_payload,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (  # noqa: E402
    ORCHESTRATOR_ROLE,
    ShieldV4ReceiptVerificationState,
    verify_shield_v4_orchestrator_receipt,
)
from adamantine.v1.integrations.shield_v4_oqs_mldsa_backend import (  # noqa: E402
    OQS_ML_DSA_MECHANISM,
    OqsMlDsaVerifierBackend,
)
from adamantine.v1.integrations.shield_v4_real_crypto_backend import (  # noqa: E402
    build_real_crypto_signature_input,
    decode_binary_signature_material,
    encode_binary_signature_material,
    make_real_crypto_signature_verifier,
)
from adamantine.v1.integrations.shield_v4_verification_audit import (  # noqa: E402
    AUDIT_ACK_SCHEMA_VERSION,
    audit_batch_sha256,
    verify_shield_v4_orchestrator_receipt_with_audit,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "adamantine"
    / "v1"
    / "fixtures"
    / "shield_v4"
    / "full_multi_repo_v4_allow_flow.json"
)


class HybridRealOqsFullChainVerifierBackend:
    """Verifier double that uses real liboqs ML-DSA and deterministic classical evidence.

    AdamantineOS remains verify-only. The test signs ML-DSA material directly with
    liboqs, then injects this verifier so the full Shield receipt path exercises
    real OQS ML-DSA verification for all component and Orchestrator ML-DSA entries.
    """

    backend_name = "shield-v4.8g-r4-real-oqs-full-chain-verifier"
    backend_version = "test-only-classical;real-liboqs-mldsa"
    supported_algorithms = ("classical-ed25519", "ml-dsa")

    def __init__(self) -> None:
        self._mldsa = OqsMlDsaVerifierBackend()

    def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> bool:
        if algorithm == "ml-dsa":
            return self._mldsa.verify_signature(
                algorithm=algorithm,
                public_key=public_key,
                message=message,
                signature=signature,
            )
        if algorithm == "classical-ed25519":
            public_key_bytes = decode_binary_signature_material(public_key, field="public_key")
            expected = _classical_signature(public_key_bytes, algorithm=algorithm, message=message)
            return hmac.compare_digest(signature, expected)
        return False


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _generate_mldsa_keypair() -> tuple[bytes, bytes]:
    with oqs.Signature(OQS_ML_DSA_MECHANISM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    assert isinstance(public_key, bytes) and public_key
    assert isinstance(secret_key, bytes) and secret_key
    return public_key, secret_key


def _classical_public_key(*, role: str, algorithm: str, key_version: int) -> bytes:
    return f"shield-v4.8g-r4-classical-public|{role}|{algorithm}|{key_version}".encode("utf-8")


def _classical_signature(public_key_bytes: bytes, *, algorithm: str, message: bytes) -> str:
    digest = hashlib.sha512(b"shield-v4.8g-r4-classical-signature|" + algorithm.encode("utf-8") + b"|" + public_key_bytes + b"|" + message).digest()
    return encode_binary_signature_material(digest, field="signature")


def _prod_key_id(*, role: str, algorithm: str, key_version: int) -> str:
    return f"prod-{role}-{algorithm}-v{key_version}"


def _realize_registry(registry: dict[str, Any]) -> tuple[dict[str, Any], dict[tuple[str, int], bytes]]:
    realized = copy.deepcopy(registry)
    mldsa_secret_keys: dict[tuple[str, int], bytes] = {}
    for key in realized["entries"]:
        role = str(key["role"])
        algorithm = str(key["algorithm"])
        key_version = int(key["key_version"])
        key["key_id"] = _prod_key_id(role=role, algorithm=algorithm, key_version=key_version)
        if algorithm == "ml-dsa":
            public_key, secret_key = _generate_mldsa_keypair()
            key["public_key"] = encode_binary_signature_material(public_key, field="public_key")
            mldsa_secret_keys[(role, key_version)] = secret_key
        else:
            key["public_key"] = encode_binary_signature_material(
                _classical_public_key(role=role, algorithm=algorithm, key_version=key_version),
                field="public_key",
            )
    return realized, mldsa_secret_keys


def _key_for(registry: dict[str, Any], *, role: str, algorithm: str, key_version: int) -> dict[str, Any]:
    for key in registry["entries"]:
        if (key["role"], key["algorithm"], key["key_version"]) == (role, algorithm, key_version):
            return key
    raise AssertionError(f"missing key for {role} {algorithm} v{key_version}")


def _mldsa_signature(secret_key: bytes, *, message: bytes) -> str:
    with oqs.Signature(OQS_ML_DSA_MECHANISM, secret_key) as signer:
        signature = signer.sign(message)
    assert isinstance(signature, bytes) and signature
    return encode_binary_signature_material(signature, field="signature")


def _resign_bundle_with_real_oqs_mldsa(
    bundle: dict[str, Any],
    *,
    role: str,
    registry: dict[str, Any],
    mldsa_secret_keys: dict[tuple[str, int], bytes],
) -> None:
    for entry in bundle["signatures"]:
        algorithm = str(entry["algorithm"])
        key_version = int(entry["key_version"])
        key = _key_for(registry, role=role, algorithm=algorithm, key_version=key_version)
        entry["key_id"] = key["key_id"]
        message = build_real_crypto_signature_input(
            algorithm=algorithm,
            standard_profile=DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[algorithm],
            domain_tag=str(entry["domain_tag"]),
            signed_payload_hash=str(entry["signed_payload_hash"]),
            key_id=str(entry["key_id"]),
            key_version=key_version,
        )
        if algorithm == "ml-dsa":
            entry["signature"] = _mldsa_signature(mldsa_secret_keys[(role, key_version)], message=message)
        elif algorithm == "classical-ed25519":
            public_key_bytes = decode_binary_signature_material(str(key["public_key"]), field="public_key")
            entry["signature"] = _classical_signature(public_key_bytes, algorithm=algorithm, message=message)
        else:  # pragma: no cover - fixture policy.v1 required signatures only.
            raise AssertionError(f"unexpected signature algorithm in fixture: {algorithm}")




def _tamper_b64u_signature(signature: str) -> str:
    raw = bytearray(decode_binary_signature_material(signature, field="signature"))
    assert raw
    raw[0] ^= 0x01
    return encode_binary_signature_material(bytes(raw), field="signature")

def _realize_full_chain_receipt() -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    fixture = _load_fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    registry, mldsa_secret_keys = _realize_registry(copy.deepcopy(fixture["trusted_key_registry"]))

    for component in receipt["component_verdicts"]:
        _resign_bundle_with_real_oqs_mldsa(
            component["signature_bundle"],
            role=COMPONENT_ROLES[str(component["component_id"])],
            registry=registry,
            mldsa_secret_keys=mldsa_secret_keys,
        )

    unsigned = unsigned_receipt_payload(receipt)
    receipt["receipt_hash"] = receipt_hash(unsigned)
    receipt["signed_payload_hash"] = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned)
    for entry in receipt["signature_bundle"]["signatures"]:
        entry["signed_payload_hash"] = receipt["signed_payload_hash"]
    _resign_bundle_with_real_oqs_mldsa(
        receipt["signature_bundle"],
        role=ORCHESTRATOR_ROLE,
        registry=registry,
        mldsa_secret_keys=mldsa_secret_keys,
    )
    return receipt, registry, fixture["expected_context_hash"], fixture["expected_request_id"], fixture["verification_time"]


def test_v48g_r4_real_oqs_mldsa_full_chain_verifies_through_adamantineos() -> None:
    assert OQS_ML_DSA_MECHANISM in tuple(oqs.get_enabled_sig_mechanisms())

    receipt, registry, expected_context_hash, expected_request_id, verification_time = _realize_full_chain_receipt()
    result = verify_shield_v4_orchestrator_receipt(
        receipt,
        expected_context_hash=expected_context_hash,
        expected_request_id=expected_request_id,
        trusted_key_registry=registry,
        verification_time=verification_time,
        signature_verifier=make_real_crypto_signature_verifier(HybridRealOqsFullChainVerifierBackend()),
    )

    assert result.state == ShieldV4ReceiptVerificationState.VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert result.reason_id == ReasonId.EVIDENCE_OK
    assert result.verified is True
    assert result.accepted_as_evidence is True
    assert result.final_approval is False
    assert result.verification_summary is not None
    assert result.verification_summary["orchestrator"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert [item["component_id"] for item in result.verification_summary["components"]] == [
        "adn",
        "dqsn",
        "guardian_wallet",
        "qwg",
        "sentinel_ai",
    ]
    assert all(key["public_key"].startswith("b64u:") and key["key_id"].startswith("prod-") for key in registry["entries"])


def test_v410b_real_oqs_mldsa_full_chain_requires_durable_audit_ack() -> None:
    class Sink:
        def __init__(self) -> None:
            self.records = ()

        def append_batch(self, records):
            self.records = records
            return {
                "schema_version": AUDIT_ACK_SCHEMA_VERSION,
                "batch_sha256": audit_batch_sha256(records),
                "record_count": len(records),
                "durably_committed": True,
            }

    receipt, registry, expected_context_hash, expected_request_id, verification_time = _realize_full_chain_receipt()
    sink = Sink()
    result = verify_shield_v4_orchestrator_receipt_with_audit(
        receipt,
        expected_context_hash=expected_context_hash,
        expected_request_id=expected_request_id,
        trusted_key_registry=registry,
        verification_time=verification_time,
        audit_sink=sink,
        artifact_transport_hash=hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        signature_verifier=make_real_crypto_signature_verifier(HybridRealOqsFullChainVerifierBackend()),
    )

    assert result.accepted_as_evidence is True
    assert result.final_approval is False
    assert len(sink.records) == 14
    assert any(
        event.get("event_type") == "signature_verification"
        and event.get("algorithm") == "ml-dsa"
        and event.get("verification_passed") is True
        for event in (json.loads(record.decode("utf-8")) for record in sink.records)
    )


def test_v48g_r4_real_oqs_mldsa_full_chain_rejects_tampered_orchestrator_mldsa() -> None:
    receipt, registry, expected_context_hash, expected_request_id, verification_time = _realize_full_chain_receipt()
    for entry in receipt["signature_bundle"]["signatures"]:
        if entry["algorithm"] == "ml-dsa":
            entry["signature"] = _tamper_b64u_signature(str(entry["signature"]))
            break
    else:  # pragma: no cover - fixture policy lock.
        raise AssertionError("missing orchestrator ml-dsa signature")

    result = verify_shield_v4_orchestrator_receipt(
        receipt,
        expected_context_hash=expected_context_hash,
        expected_request_id=expected_request_id,
        trusted_key_registry=registry,
        verification_time=verification_time,
        signature_verifier=make_real_crypto_signature_verifier(HybridRealOqsFullChainVerifierBackend()),
    )

    assert result.state == ShieldV4ReceiptVerificationState.REJECTED_SIGNATURE_INVALID
    assert result.reason_id == ReasonId.EQC_INVALID_SHIELD_BUNDLE
    assert result.final_approval is False
