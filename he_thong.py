"""Merchant--Proxy--Issuer model and the seven-stage verification pipeline."""
from __future__ import annotations

import copy
import datetime as dt
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from cryptography import x509

from audit_log import AuditLog
from ca_service import CAUnavailable, DemoCA
from nonce_store import (
    NONCE_TTL_MARGIN_SECONDS,
    NONCE_TTL_SECONDS,
    TIMESTAMP_WINDOW_SECONDS,
    InMemoryReplayStore,
    ReplayStore,
    ReplayStoreUnavailable,
)
from rsa_crypto import (
    CanonicalizationError,
    canonical_json_bytes,
    generate_nonce,
    generate_private_key,
    sha256_hex,
    sign,
    strict_json_loads,
    verify,
)

UTC = dt.timezone.utc
PAYLOAD_FIELDS = frozenset(
    {"MessageID", "MerchantID", "CardToken", "Amount", "Currency", "Timestamp", "Nonce"}
)
ENVELOPE_FIELDS = frozenset({"payload", "MessageHash", "Signature", "CertificateID"})
MAX_AMOUNT = (1 << 63) - 1
MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
MERCHANT_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,63}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
CERT_ID_RE = re.compile(r"^sha256:[0-9A-F]{64}$")


class Clock:
    def now(self) -> dt.datetime:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> dt.datetime:
        return dt.datetime.now(UTC)


class FrozenClock(Clock):
    """Injectable clock for reproducible scenarios and tests."""

    def __init__(self, now: dt.datetime) -> None:
        if now.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime")
        self._now = now.astimezone(UTC)

    def now(self) -> dt.datetime:
        return self._now

    def advance(self, delta: dt.timedelta) -> None:
        self._now += delta


@dataclass
class Environment:
    clock: Clock
    ca: DemoCA
    issuer: "Issuer"
    merchant: "Merchant"
    attacker: "Merchant"
    data: dict[str, Any]


def format_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    if format_timestamp(parsed) != value:
        raise ValueError("timestamp is not in canonical UTC format")
    return parsed


def validate_payload(payload: Any) -> str | None:
    """Return a stable decision code when the payload does not meet the schema."""
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        return "MALFORMED"
    if not isinstance(payload["MessageID"], str) or not MESSAGE_ID_RE.fullmatch(payload["MessageID"]):
        return "MALFORMED"
    if not isinstance(payload["MerchantID"], str) or not MERCHANT_ID_RE.fullmatch(payload["MerchantID"]):
        return "MALFORMED"
    if not isinstance(payload["CardToken"], str) or not TOKEN_RE.fullmatch(payload["CardToken"]):
        return "MALFORMED"
    amount = payload["Amount"]
    if isinstance(amount, bool) or not isinstance(amount, int) or not (1 <= amount <= MAX_AMOUNT):
        return "MALFORMED"
    if not isinstance(payload["Currency"], str) or not re.fullmatch(r"[A-Z]{3}", payload["Currency"]):
        return "MALFORMED"
    if not isinstance(payload["Timestamp"], str):
        return "MALFORMED"
    try:
        parse_timestamp(payload["Timestamp"])
    except ValueError:
        return "MALFORMED"
    if not isinstance(payload["Nonce"], str) or not NONCE_RE.fullmatch(payload["Nonce"]):
        return "MALFORMED"
    return None


def parse_incoming_json(raw: str | bytes) -> Any:
    """Network-boundary parser; call before application code sees a dict."""
    try:
        return strict_json_loads(raw)
    except CanonicalizationError as exc:
        raise ValueError("malformed or ambiguous JSON") from exc


class Merchant:
    def __init__(
        self,
        merchant_id: str,
        ca: DemoCA,
        clock: Clock,
        key_size: int = 2048,
    ) -> None:
        if not MERCHANT_ID_RE.fullmatch(merchant_id):
            raise ValueError("invalid MerchantID")
        self.merchant_id = merchant_id
        self.clock = clock
        self.private_key = generate_private_key(key_size)
        self.certificate_id, self.certificate = ca.issue(merchant_id, self.private_key.public_key())

    def make_payload(
        self,
        *,
        message_id: str,
        amount: int = 150_000,
        card_token: str = "tok_9f2e77ab",
        currency: str = "VND",
        timestamp: dt.datetime | None = None,
        nonce: str | None = None,
        merchant_id: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "MessageID": message_id,
            "MerchantID": merchant_id or self.merchant_id,
            "CardToken": card_token,
            "Amount": amount,
            "Currency": currency,
            "Timestamp": format_timestamp(timestamp or self.clock.now()),
            "Nonce": nonce or generate_nonce(),
        }
        return payload

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        code = validate_payload(payload)
        if code:
            raise ValueError("invalid payload: %s" % code)
        data = canonical_json_bytes(payload)
        return {
            "payload": copy.deepcopy(payload),
            "MessageHash": sha256_hex(data),
            "Signature": sign(self.private_key, data).hex(),
            "CertificateID": self.certificate_id,
        }

    def create_packet(self, **kwargs: Any) -> dict[str, Any]:
        return self.sign_payload(self.make_payload(**kwargs))


class Issuer:
    """Issuer-side verifier with explicit fail-closed replay handling."""

    def __init__(
        self,
        ca: DemoCA,
        clock: Clock,
        replay_store: ReplayStore | None = None,
        audit_log: AuditLog | None = None,
        window_seconds: int = TIMESTAMP_WINDOW_SECONDS,
    ) -> None:
        self.ca = ca
        self.clock = clock
        required_nonce_ttl = max(
            NONCE_TTL_SECONDS,
            2 * window_seconds + NONCE_TTL_MARGIN_SECONDS,
        )
        if replay_store is None:
            self.replay_store = InMemoryReplayStore(nonce_ttl=required_nonce_ttl)
        else:
            configured_nonce_ttl = getattr(replay_store, "nonce_ttl", None)
            if configured_nonce_ttl is None or configured_nonce_ttl < required_nonce_ttl:
                raise ValueError(
                    "replay store nonce_ttl must be at least %d seconds" % required_nonce_ttl
                )
            self.replay_store = replay_store
        self.audit_log = audit_log or AuditLog()
        self.window_seconds = window_seconds
        self.registry: dict[str, set[str]] = {}
        self._crl_cache: x509.CertificateRevocationList | None = None

    def register_merchant(self, merchant_id: str, cert_id: str) -> None:
        if not MERCHANT_ID_RE.fullmatch(merchant_id):
            raise ValueError("invalid MerchantID")
        if not CERT_ID_RE.fullmatch(cert_id):
            raise ValueError("invalid certificate fingerprint")
        self.registry.setdefault(merchant_id, set()).add(cert_id)

    def _get_current_crl(self) -> x509.CertificateRevocationList | None:
        now = self.clock.now().astimezone(UTC)
        try:
            # Prefer the CA's freshest CRL; use the last-known one only while valid.
            self._crl_cache = self.ca.get_crl()
        except CAUnavailable:
            if self._crl_cache is not None and self._crl_cache.next_update_utc > now:
                return self._crl_cache
            return None
        return self._crl_cache

    def verify_packet(
        self,
        packet: Any,
        mode: str = "live",
        trace: list[str] | None = None,
    ) -> str:
        """Run T0, T1, T1b, T2, T3, T4 and T5; return one decision code.

        ``mode='postcheck'`` omits freshness and replay consumption so a stored
        message can be re-verified. It does not create trusted time evidence.
        """
        if mode not in {"live", "postcheck"}:
            raise ValueError("mode must be 'live' or 'postcheck'")
        steps = trace if trace is not None else []

        def finish(code: str) -> str:
            self._append_audit(code, packet, mode)
            return code

        if not isinstance(packet, dict) or set(packet) != ENVELOPE_FIELDS:
            steps.append("T0 structure: reject -> MALFORMED")
            return finish("MALFORMED")
        payload = packet.get("payload")
        code = validate_payload(payload)
        if code:
            steps.append("T0 payload schema: reject -> MALFORMED")
            return finish(code)
        if not isinstance(packet.get("MessageHash"), str) or not HASH_RE.fullmatch(packet["MessageHash"]):
            steps.append("T0 message hash format: reject -> MALFORMED")
            return finish("MALFORMED")
        signature_hex = packet.get("Signature")
        if (
            not isinstance(signature_hex, str)
            or len(signature_hex) > 2048
            or not SIGNATURE_RE.fullmatch(signature_hex)
        ):
            steps.append("T0 signature encoding: reject -> MALFORMED")
            return finish("MALFORMED")
        cert_id = packet.get("CertificateID")
        if not isinstance(cert_id, str) or not CERT_ID_RE.fullmatch(cert_id):
            steps.append("T0 certificate id format: reject -> MALFORMED")
            return finish("MALFORMED")
        steps.append("T0 schema and encoding: pass")

        now = self.clock.now().astimezone(UTC)
        try:
            signed_at = parse_timestamp(payload["Timestamp"])
            crl = self._get_current_crl()
            cert_result = self.ca.validate_certificate(
                cert_id,
                signed_at,
                crl,
                revocation_time=now,
                require_current_validity=(mode == "live"),
            )
        except (ValueError, TypeError):
            steps.append("T1 certificate input: reject -> MALFORMED")
            return finish("MALFORMED")
        if cert_result.code != "OK" or cert_result.certificate is None:
            steps.append("T1 certificate/CRL: reject -> %s" % cert_result.code)
            return finish(cert_result.code)
        cert = cert_result.certificate
        steps.append("T1 certificate chain, validity, revocation and key policy: pass")

        merchant_id = payload["MerchantID"]
        cert_identity = self.ca.merchant_identity(cert)
        if cert_identity != merchant_id or cert_id not in self.registry.get(merchant_id, set()):
            steps.append("T1b certificate identity/registry: reject -> SIGNER_NOT_AUTHORIZED")
            return finish("SIGNER_NOT_AUTHORIZED")
        steps.append("T1b certificate identity and merchant registry: pass")

        if mode == "live":
            delta = (now - signed_at).total_seconds()
            if delta > self.window_seconds:
                steps.append("T2 timestamp: outside window -> TIMESTAMP_TOO_OLD")
                return finish("TIMESTAMP_TOO_OLD")
            if delta < -self.window_seconds:
                steps.append("T2 timestamp: future value outside window -> TIMESTAMP_IN_FUTURE")
                return finish("TIMESTAMP_IN_FUTURE")
            steps.append("T2 timestamp window: pass")
            try:
                if self.replay_store.nonce_seen(merchant_id, payload["Nonce"], now.timestamp()):
                    steps.append("T3 nonce: already used -> REPLAY_DETECTED")
                    return finish("REPLAY_DETECTED")
            except ReplayStoreUnavailable:
                steps.append("T3 nonce store unavailable: fail closed")
                return finish("SERVICE_UNAVAILABLE")
            steps.append("T3 nonce lookup: pass")

        try:
            canonical = canonical_json_bytes(payload)
        except CanonicalizationError:
            steps.append("T4 canonicalization: reject -> MALFORMED")
            return finish("MALFORMED")
        computed_hash = sha256_hex(canonical)
        if computed_hash != packet["MessageHash"]:
            steps.append("T4 message digest: mismatch -> INTEGRITY_VIOLATION")
            return finish("INTEGRITY_VIOLATION")
        steps.append("T4 message digest: pass")

        public_key = cert.public_key()
        signature = bytes.fromhex(packet["Signature"])
        if not verify(public_key, canonical, signature):
            steps.append("T5 RSA-PSS signature: reject -> SIGNATURE_INVALID")
            return finish("SIGNATURE_INVALID")
        steps.append("T5 RSA-PSS signature: pass")

        if mode == "live":
            try:
                conflict = self.replay_store.consume(
                    merchant_id,
                    payload["Nonce"],
                    payload["MessageID"],
                    now.timestamp(),
                )
            except ReplayStoreUnavailable:
                steps.append("T3 replay/idempotency commit unavailable: fail closed")
                return finish("SERVICE_UNAVAILABLE")
            if conflict:
                steps.append("T3 atomic replay/idempotency commit: reject -> %s" % conflict)
                return finish(conflict)
            steps.append("T3 atomic nonce and MessageID reservation: pass")

        return finish("SIGNATURE_VALID")

    def _append_audit(self, code: str, packet: Any, mode: str) -> None:
        payload = packet.get("payload", {}) if isinstance(packet, dict) else {}
        if not isinstance(payload, dict):
            payload = {}
        safe_packet = packet if isinstance(packet, dict) else {}
        event = {
            "decision": code,
            "mode": mode,
            "observed_at": format_timestamp(self.clock.now()),
            "message_id": payload.get("MessageID", "UNKNOWN"),
            "merchant_id": payload.get("MerchantID", "UNKNOWN"),
            "certificate_id": safe_packet.get("CertificateID", "UNKNOWN"),
            "message_hash": safe_packet.get("MessageHash", "UNKNOWN"),
        }
        self.audit_log.append(event)


class Proxy:
    """Untrusted relay used by scenarios to forward or mutate an envelope."""

    @staticmethod
    def forward(packet: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(packet)

    @staticmethod
    def modify(packet: dict[str, Any], field: str, value: Any) -> dict[str, Any]:
        result = copy.deepcopy(packet)
        result["payload"][field] = value
        return result


def create_environment(
    *,
    clock: Clock | None = None,
    audit_path: str | None = None,
    replay_store: ReplayStore | None = None,
) -> Environment:
    clock = clock or SystemClock()
    ca = DemoCA(clock.now)
    audit = AuditLog(audit_path)
    issuer = Issuer(ca, clock, replay_store=replay_store, audit_log=audit)
    merchant = Merchant("MERCH-01", ca, clock)
    attacker = Merchant("ATTACK-01", ca, clock)
    issuer.register_merchant(merchant.merchant_id, merchant.certificate_id)
    issuer.register_merchant(attacker.merchant_id, attacker.certificate_id)
    return Environment(clock, ca, issuer, merchant, attacker, {})
