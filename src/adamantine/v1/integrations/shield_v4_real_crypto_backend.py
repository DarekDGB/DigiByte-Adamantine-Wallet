from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping
from typing import Any, Protocol, TypeVar

from adamantine.v1.contracts.shield_orchestrator_receipt_v4 import (
    ALGORITHM_STANDARD_PROFILES,
    ALLOWED_ALGORITHMS,
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
)
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import TrustedShieldV4Key
from adamantine.v1.integrations.shield_v4_work_budget import (
    MAX_TEXT_FIELD_BYTES,
    ShieldV4WorkBudgetError,
    require_bounded_text,
)

REAL_CRYPTO_SIGNATURE_INPUT_PREFIX = "DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT"
REAL_SIGNATURE_ENCODING_PREFIX = "b64u:"
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_ALLOWED_DOMAIN_TAGS = frozenset({COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN})
_SIGNATURE_ENTRY_FIELDS = frozenset(
    {"algorithm", "standard_profile", "key_id", "key_version", "signed_payload_hash", "domain_tag", "signature"}
)
_T = TypeVar("_T")
_TEST_ONLY_MARKERS = ("test-only",)
_TEST_ONLY_PREFIXES = ("test-",)


class ShieldV4RealCryptoBackendError(ValueError):
    """Base fail-closed error for AdamantineOS Shield v4 real-crypto verification."""


class ShieldV4RealCryptoBackendUnavailable(ShieldV4RealCryptoBackendError):
    """Raised when the configured production verifier lacks a required algorithm."""


class ShieldV4RealCryptoMaterialError(ShieldV4RealCryptoBackendError):
    """Raised when test-only material reaches the AdamantineOS real verifier boundary."""


class ShieldV4RealCryptoVerifierBackend(Protocol):
    """AdamantineOS verify-only backend contract for Shield v4 signatures.

    AdamantineOS does not sign Shield receipts or transactions. Implementations
    only expose verification for deployment-controlled real crypto backends.
    """

    backend_name: str
    backend_version: str
    supported_algorithms: tuple[str, ...]

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        """Return True only when the signature verifies under the supplied public key."""


RealCryptoSignatureVerifier = Callable[[Mapping[str, Any], TrustedShieldV4Key], bool]


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty string")
    if value != value.strip():
        raise ShieldV4RealCryptoBackendError(f"{field} must not contain surrounding whitespace")
    return value


def _call_backend_operation(operation: str, callback: Callable[[], _T]) -> _T:
    try:
        return callback()
    except ShieldV4RealCryptoBackendError:
        raise
    except Exception as exc:
        raise ShieldV4RealCryptoBackendError(f"real crypto backend {operation} failed closed") from exc


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShieldV4RealCryptoBackendError(f"{field} must be positive integer")
    return value


def _require_hash(value: Any, *, field: str) -> str:
    clean = _require_non_empty_str(value, field=field)
    if len(clean) != 64:
        raise ShieldV4RealCryptoBackendError(f"{field} must be 64-character sha256 hex")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} must be sha256 hex") from exc
    if clean != clean.lower():
        raise ShieldV4RealCryptoBackendError(f"{field} must be lowercase sha256 hex")
    return clean


def _require_supported_algorithm(value: Any) -> str:
    algorithm = _require_non_empty_str(value, field="algorithm")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise ShieldV4RealCryptoBackendError("algorithm must be supported by Shield v4 policy")
    return algorithm


def _require_supported_standard_profile(*, algorithm: str, standard_profile: Any) -> str:
    clean_profile = _require_non_empty_str(standard_profile, field="standard_profile")
    if clean_profile not in ALGORITHM_STANDARD_PROFILES.get(algorithm, ()):  # defensive even after contract validation.
        raise ShieldV4RealCryptoBackendError("unsupported Shield v4 signature standard_profile")
    return clean_profile


def _reject_test_only_text(value: str, *, field: str) -> None:
    try:
        bounded = require_bounded_text(value, field_name=field)
    except ShieldV4WorkBudgetError as exc:
        raise ShieldV4RealCryptoMaterialError(f"{field} exceeds text byte budget") from exc
    clean = bounded.strip().lower()
    if any(marker in clean for marker in _TEST_ONLY_MARKERS) or any(
        clean.startswith(prefix) for prefix in _TEST_ONLY_PREFIXES
    ):
        raise ShieldV4RealCryptoMaterialError(f"{field} must not contain test-only material")


def reject_test_only_key_material(key: TrustedShieldV4Key) -> None:
    """Fail closed if deterministic-test keys reach AdamantineOS real verification."""

    _reject_test_only_text(key.key_id, field="key_id")
    _reject_test_only_text(key.public_key, field="public_key")


def encode_binary_signature_material(raw: bytes, *, field: str = "signature") -> str:
    """Encode real binary signature/key material using unpadded base64url."""

    if not isinstance(raw, bytes) or not raw:
        raise ShieldV4RealCryptoBackendError(f"{field} bytes must be non-empty")
    maximum_raw_bytes = (
        (MAX_TEXT_FIELD_BYTES - len(REAL_SIGNATURE_ENCODING_PREFIX)) * 3
    ) // 4
    if len(raw) > maximum_raw_bytes:
        raise ShieldV4RealCryptoBackendError(f"{field} exceeds encoding byte budget")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    rendered = f"{REAL_SIGNATURE_ENCODING_PREFIX}{encoded}"
    try:
        return require_bounded_text(rendered, field_name=field)
    except ShieldV4WorkBudgetError as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} exceeds encoding byte budget") from exc


def decode_binary_signature_material(encoded: Any, *, field: str = "signature") -> bytes:
    """Decode an explicit ``b64u:`` signature/key encoding into bytes."""

    try:
        bounded = require_bounded_text(encoded, field_name=field)
    except ShieldV4WorkBudgetError as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} exceeds encoding byte budget") from exc
    clean = _require_non_empty_str(bounded, field=field)
    if not clean.startswith(REAL_SIGNATURE_ENCODING_PREFIX):
        raise ShieldV4RealCryptoBackendError(f"{field} must use b64u encoding")
    body = clean[len(REAL_SIGNATURE_ENCODING_PREFIX) :]
    if not body:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must be non-empty")
    if "=" in body:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must be unpadded")
    if set(body) - _BASE64URL_ALPHABET:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload is invalid")
    try:
        decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload is invalid") from exc
    if not decoded:  # pragma: no cover - base64url cannot reach this after the body check.
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must decode to non-empty bytes")
    return decoded


def build_real_crypto_signature_input(
    *,
    algorithm: str,
    standard_profile: str,
    domain_tag: str,
    signed_payload_hash: str,
    key_id: str,
    key_version: int,
) -> bytes:
    """Build the exact production-verification message bytes for Shield v4.

    The message binds the already domain-separated signed payload hash to the
    algorithm, standard profile, key id, and key version. This prevents an
    attacker from flipping a valid FN-DSA/Falcon profile into another profile.
    """

    clean_algorithm = _require_supported_algorithm(algorithm)
    clean_domain = _require_non_empty_str(domain_tag, field="domain_tag")
    if clean_domain not in _ALLOWED_DOMAIN_TAGS:
        raise ShieldV4RealCryptoBackendError("domain_tag must be a Shield v4 signing domain")
    clean_profile = _require_supported_standard_profile(
        algorithm=clean_algorithm,
        standard_profile=standard_profile,
    )
    clean_hash = _require_hash(signed_payload_hash, field="signed_payload_hash")
    clean_key_id = _require_non_empty_str(key_id, field="key_id")
    clean_key_version = _require_positive_int(key_version, field="key_version")
    return "\n".join(
        (
            REAL_CRYPTO_SIGNATURE_INPUT_PREFIX,
            clean_domain,
            clean_hash,
            clean_algorithm,
            clean_profile,
            clean_key_id,
            str(clean_key_version),
        )
    ).encode("utf-8")


def _require_backend_supports_algorithm(backend: ShieldV4RealCryptoVerifierBackend, algorithm: str) -> None:
    try:
        supported = tuple(getattr(backend, "supported_algorithms", ()))
    except Exception as exc:
        raise ShieldV4RealCryptoBackendError("real crypto backend algorithm discovery failed closed") from exc
    if algorithm not in supported:
        raise ShieldV4RealCryptoBackendUnavailable("real crypto backend does not support required algorithm")


def verify_signature_entry_with_real_backend(
    entry: Mapping[str, Any],
    key: TrustedShieldV4Key,
    *,
    backend: ShieldV4RealCryptoVerifierBackend,
) -> bool:
    """Verify one Shield v4 signature entry with AdamantineOS real crypto backend."""

    if not isinstance(entry, Mapping):
        raise ShieldV4RealCryptoBackendError("signature entry must be mapping")
    if set(entry.keys()) != _SIGNATURE_ENTRY_FIELDS:
        raise ShieldV4RealCryptoBackendError("signature entry fields must match required schema")
    reject_test_only_key_material(key)
    algorithm = _require_supported_algorithm(entry.get("algorithm"))
    standard_profile = _require_supported_standard_profile(
        algorithm=algorithm,
        standard_profile=entry.get("standard_profile"),
    )
    key_id = _require_non_empty_str(entry.get("key_id"), field="key_id")
    key_version = _require_positive_int(entry.get("key_version"), field="key_version")
    if (key.algorithm, key.key_id, key.key_version) != (algorithm, key_id, key_version):
        raise ShieldV4RealCryptoBackendError("signature entry does not match trusted key")
    public_key = _require_non_empty_str(key.public_key, field="public_key")
    decode_binary_signature_material(public_key, field="public_key")
    _require_backend_supports_algorithm(backend, algorithm)
    message = build_real_crypto_signature_input(
        algorithm=algorithm,
        standard_profile=standard_profile,
        domain_tag=_require_non_empty_str(entry.get("domain_tag"), field="domain_tag"),
        signed_payload_hash=_require_hash(entry.get("signed_payload_hash"), field="signed_payload_hash"),
        key_id=key_id,
        key_version=key_version,
    )
    signature = _require_non_empty_str(entry.get("signature"), field="signature")
    decode_binary_signature_material(signature, field="signature")
    verified = _call_backend_operation(
        "verify",
        lambda: backend.verify_signature(
            algorithm=algorithm,
            public_key=public_key,
            message=message,
            signature=signature,
        ),
    )
    if not isinstance(verified, bool):
        raise ShieldV4RealCryptoBackendError("real crypto backend verify must return bool")
    return verified


def make_real_crypto_signature_verifier(
    backend: ShieldV4RealCryptoVerifierBackend,
) -> RealCryptoSignatureVerifier:
    """Adapt a real verifier backend to AdamantineOS Shield v4 verifier injection."""

    def _verify(entry: Mapping[str, Any], key: TrustedShieldV4Key) -> bool:
        return verify_signature_entry_with_real_backend(entry, key, backend=backend)

    return _verify
