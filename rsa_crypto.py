"""Cryptographic primitives used by the educational payment-message prototype.

The JSON encoding in this module is a deliberately small, versioned profile for
this project. It is deterministic for the restricted payload schema, but it is
not a claim of full RFC 8785/JCS conformance. For interoperable deployments,
replace it with a tested JCS implementation and publish test vectors.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import unicodedata
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGN_SCHEME = "RSASSA-PSS-SHA256"
HASH_NAME = "SHA-256"
MIN_KEY_BITS = 2048
PUBLIC_EXPONENT = 65537
PSS_SALT_BYTES = 32
NONCE_BYTES = 16  # 128 bits
MAX_JSON_BYTES = 16_384


class CanonicalizationError(ValueError):
    """Raised when JSON cannot be represented unambiguously by this profile."""


def _normalize_json(value: Any) -> Any:
    """Return a JSON-compatible value with strings normalized to Unicode NFC."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        # Monetary fields are integers; rejecting floats avoids cross-runtime
        # number formatting differences and NaN/Infinity ambiguity.
        raise CanonicalizationError("floating-point values are not allowed")
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            nkey = unicodedata.normalize("NFC", key)
            if nkey in normalized:
                raise CanonicalizationError("object keys collide after NFC normalization")
            normalized[nkey] = _normalize_json(item)
        return normalized
    raise CanonicalizationError("unsupported JSON value: %s" % type(value).__name__)


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Serialize a JSON object deterministically using the project's v1 profile."""
    if not isinstance(value, dict):
        raise CanonicalizationError("top-level JSON value must be an object")
    normalized = _normalize_json(value)
    try:
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def strict_json_loads(raw: str | bytes) -> Any:
    """Parse bounded JSON and reject ambiguity, duplicate keys, and floats."""
    if isinstance(raw, bytes):
        raw_size = len(raw)
    elif isinstance(raw, str):
        try:
            raw_size = len(raw.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise CanonicalizationError("JSON contains invalid Unicode") from exc
    else:
        raise CanonicalizationError("JSON input must be str or bytes")
    if raw_size > MAX_JSON_BYTES:
        raise CanonicalizationError("JSON input exceeds %d bytes" % MAX_JSON_BYTES)

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            nkey = unicodedata.normalize("NFC", key)
            if nkey in obj:
                raise CanonicalizationError("duplicate JSON key: %s" % key)
            obj[nkey] = value
        return obj

    try:
        return json.loads(
            raw,
            object_pairs_hook=object_pairs_hook,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except CanonicalizationError:
        raise
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
        raise CanonicalizationError("invalid JSON") from exc


def _reject_constant(value: str) -> None:
    raise CanonicalizationError("non-finite JSON number is not allowed: %s" % value)


def _reject_float(value: str) -> None:
    raise CanonicalizationError("floating-point values are not allowed: %s" % value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_nonce() -> str:
    """Return a cryptographically random 128-bit nonce encoded as 32 hex chars."""
    return secrets.token_hex(NONCE_BYTES)


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA key for the demo; production keys belong in an HSM/KMS."""
    if key_size < MIN_KEY_BITS:
        raise ValueError("RSA keys shorter than %d bits are forbidden" % MIN_KEY_BITS)
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)


def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=PSS_SALT_BYTES,
    )


def sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Sign bytes with RSASSA-PSS using SHA-256 and a 32-byte salt."""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    return private_key.sign(message, _pss_padding(), hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PSS signature; malformed or invalid signatures return False."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    try:
        public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
