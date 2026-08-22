from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import platform
import statistics
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable

from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import to_canonical_json
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    _verify_test_only_signature,
)
from adamantine.v1.integrations.shield_v4_verification_audit import (
    AUDIT_ACK_SCHEMA_VERSION,
    ShieldV4AuditedVerificationError,
    audit_batch_sha256,
    verify_shield_v4_orchestrator_receipt_with_audit,
)
from adamantine.v1.integrations.shield_v4_work_budget import MAX_TEXT_FIELD_BYTES

SCHEMA_VERSION = "shield-v4-v410c-performance-v1"
REPOSITORY = "DigiByte-AdamantineOS"
REQUIRED_FIXTURE_SHA256 = "b1031e999b87f61643748848e6d121f153c3cbdc7c87ceef9a62c766bc8b7ced"
WARMUPS = 20
SAMPLES = 200
VALID_LIMIT_MS = 50.0
OVERSIZE_REJECTION_LIMIT_MS = 20.0
PINNED_SOFTWARE = {
    "pip": "25.2",
    "setuptools": "80.9.0",
    "wheel": "0.45.1",
    "pytest": "8.4.1",
    "pytest-cov": "6.2.1",
}
ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT
    / "src"
    / "adamantine"
    / "v1"
    / "fixtures"
    / "shield_v4"
    / "full_multi_repo_v4_allow_flow.json"
)


class _AcknowledgingSink:
    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        return {
            "schema_version": AUDIT_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


def _percentile_95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def _measure(operation: Callable[[], None]) -> dict[str, float]:
    for _ in range(WARMUPS):
        operation()
    timings_ms: list[float] = []
    for _ in range(SAMPLES):
        started = time.perf_counter_ns()
        operation()
        timings_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "median_ms": round(statistics.median(timings_ms), 6),
        "p95_ms": round(_percentile_95(timings_ms), 6),
    }


def _build_operations(
    fixture: dict[str, Any],
) -> tuple[Callable[[], None], Callable[[], None]]:
    sink = _AcknowledgingSink()
    receipt = fixture["receipt"]
    artifact_transport_hash = hashlib.sha256(
        to_canonical_json(receipt).encode("utf-8"),
    ).hexdigest()
    common = {
        "expected_context_hash": fixture["expected_context_hash"],
        "expected_request_id": fixture["expected_request_id"],
        "trusted_key_registry": fixture["trusted_key_registry"],
        "verification_time": fixture["verification_time"],
        "audit_sink": sink,
        "artifact_transport_hash": artifact_transport_hash,
        "signature_verifier": _verify_test_only_signature,
    }
    oversized_receipt = copy.deepcopy(receipt)
    oversized_receipt["component_verdicts"][0]["metadata"]["oversized"] = (
        "x" * (MAX_TEXT_FIELD_BYTES + 1)
    )

    def valid_operation() -> None:
        result = verify_shield_v4_orchestrator_receipt_with_audit(
            receipt,
            **common,
        )
        if not result.accepted_as_evidence or result.final_approval:
            raise RuntimeError("valid benchmark fixture did not remain evidence only")

    def oversize_rejection_operation() -> None:
        try:
            verify_shield_v4_orchestrator_receipt_with_audit(
                oversized_receipt,
                **common,
            )
        except ShieldV4AuditedVerificationError as exc:
            if str(exc) == "V4_CONTRACT_INVALID":
                return
        raise RuntimeError("oversize benchmark fixture was not rejected fail closed")

    return valid_operation, oversize_rejection_operation


def _software_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for distribution in PINNED_SOFTWARE:
        try:
            versions[distribution] = version(distribution)
        except PackageNotFoundError:
            versions[distribution] = "unavailable"
    return versions


def main() -> int:
    fixture_bytes = FIXTURE_PATH.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    if fixture_sha256 != REQUIRED_FIXTURE_SHA256:
        raise RuntimeError("V4.10-C benchmark fixture digest mismatch")
    fixture = json.loads(fixture_bytes.decode("utf-8"))
    valid_operation, oversize_rejection_operation = _build_operations(fixture)
    valid = _measure(valid_operation)
    oversize_rejection = _measure(oversize_rejection_operation)
    software = _software_versions()
    valid["limit_ms"] = VALID_LIMIT_MS
    oversize_rejection["limit_ms"] = OVERSIZE_REJECTION_LIMIT_MS
    environment = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "pythonhashseed": os.environ.get("PYTHONHASHSEED", ""),
        "tz": os.environ.get("TZ", ""),
        "lc_all": os.environ.get("LC_ALL", ""),
    }
    expected_environment = {
        "python": "3.11.15",
        "pythonhashseed": "0",
        "tz": "UTC",
        "lc_all": "C.UTF-8",
    }
    passed = (
        valid["p95_ms"] <= VALID_LIMIT_MS
        and oversize_rejection["p95_ms"] <= OVERSIZE_REJECTION_LIMIT_MS
        and software == PINNED_SOFTWARE
        and all(
            environment[field] == expected
            for field, expected in expected_environment.items()
        )
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "fixture_sha256": fixture_sha256,
        "environment": environment,
        "software": software,
        "warmups": WARMUPS,
        "samples": SAMPLES,
        "valid": valid,
        "oversize_rejection": oversize_rejection,
        "status": "PASS" if passed else "FAIL",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
