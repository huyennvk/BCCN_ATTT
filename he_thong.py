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

        Raw JSON text/bytes are parsed here with the strict bounded parser.
        Already-decoded dictionaries are accepted for in-process scenarios; a
        network ingress must pass the original raw body so duplicate keys and
        the 16 KiB limit can be enforced before decoding.

        ``mode='postcheck'`` omits freshness and replay consumption so a stored
        message can be re-verified. It does not create trusted time evidence.
        """
        if mode not in {"live", "postcheck"}:
            raise ValueError("mode must be 'live' or 'postcheck'")
        steps = trace if trace is not None else []

        def finish(code: str) -> str:
            self._append_audit(code, packet, mode)
            return code

        if isinstance(packet, (str, bytes)):
            try:
                packet = parse_incoming_json(packet)
                steps.append("T0 JSON parsing: PASS; strict 16 KiB parser accepted the raw body")
            except ValueError:
                steps.append(
                    "T0 JSON parsing: invalid, ambiguous or over 16 KiB -> MALFORMED"
                )
                return finish("MALFORMED")

        if not isinstance(packet, dict):
            steps.append(
                "T0 envelope: expected JSON object/dict; received %s -> MALFORMED"
                % type(packet).__name__
            )
            return finish("MALFORMED")
        expected_envelope = sorted(ENVELOPE_FIELDS)
        received_envelope = sorted(str(key) for key in packet)
        missing_envelope = sorted(ENVELOPE_FIELDS - set(packet))
        extra_envelope = sorted(str(key) for key in set(packet) - ENVELOPE_FIELDS)
        steps.append(
            "T0 envelope fields: received=[%s]; expected=[%s]"
            % (", ".join(received_envelope), ", ".join(expected_envelope))
        )
        if missing_envelope or extra_envelope:
            steps.append(
                "T0 envelope result: missing=[%s], extra=[%s] -> MALFORMED"
                % (", ".join(missing_envelope), ", ".join(extra_envelope))
            )
            return finish("MALFORMED")

        payload = packet.get("payload")
        code = validate_payload(payload)
        if code:
            if isinstance(payload, dict):
                payload_fields = sorted(str(key) for key in payload)
                missing_payload = sorted(PAYLOAD_FIELDS - set(payload))
                extra_payload = sorted(str(key) for key in set(payload) - PAYLOAD_FIELDS)
                steps.append(
                    "T0 payload fields: received=[%s]; missing=[%s]; extra=[%s]"
                    % (", ".join(payload_fields), ", ".join(missing_payload), ", ".join(extra_payload))
                )
            else:
                steps.append("T0 payload: expected object/dict; received %s" % type(payload).__name__)
            steps.append("T0 payload schema: reject -> MALFORMED")
            return finish(code)
        steps.append(
            "T0 payload schema: 7/7 required fields present; Amount=%s %s; MerchantID=%s; MessageID=%s"
            % (payload["Amount"], payload["Currency"], payload["MerchantID"], payload["MessageID"])
        )

        message_hash = packet.get("MessageHash")
        if not isinstance(message_hash, str) or not HASH_RE.fullmatch(message_hash):
            length = len(message_hash) if isinstance(message_hash, str) else "n/a"
            steps.append(
                "T0 MessageHash encoding: expected 64 lowercase hex chars; received length=%s -> MALFORMED"
                % length
            )
            return finish("MALFORMED")
        steps.append("T0 MessageHash encoding: 64 lowercase hex chars")

        signature_hex = packet.get("Signature")
        if (
            not isinstance(signature_hex, str)
            or len(signature_hex) > 2048
            or not SIGNATURE_RE.fullmatch(signature_hex)
        ):
            length = len(signature_hex) if isinstance(signature_hex, str) else "n/a"
            steps.append(
                "T0 Signature encoding: expected even-length hex up to 2048 chars; received length=%s -> MALFORMED"
                % length
            )
            return finish("MALFORMED")
        steps.append(
            "T0 Signature encoding: %d hex chars (%d bytes)"
            % (len(signature_hex), len(signature_hex) // 2)
        )

        cert_id = packet.get("CertificateID")
        if not isinstance(cert_id, str) or not CERT_ID_RE.fullmatch(cert_id):
            steps.append("T0 CertificateID encoding: expected sha256:<64 uppercase hex chars> -> MALFORMED")
            return finish("MALFORMED")
        steps.append("T0 CertificateID: %s" % cert_id)
        steps.append("T0 result: PASS; T0 makes no transformation and forwards the received packet unchanged to T1")

        now = self.clock.now().astimezone(UTC)
        steps.append(
            "T1 inputs: CertificateID=%s; signed Timestamp=%s; verifier now=%s"
            % (cert_id, payload["Timestamp"], format_timestamp(now))
        )
        try:
            signed_at = parse_timestamp(payload["Timestamp"])
            crl = self._get_current_crl()
            if crl is None:
                steps.append("T1 CRL input: unavailable (no current CRL and no unexpired cache)")
            else:
                steps.append(
                    "T1 CRL input: lastUpdate=%s; nextUpdate=%s"
                    % (crl.last_update_utc.isoformat(), crl.next_update_utc.isoformat())
                )
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
            steps.append(
                "T1 certificate/CRL result: CertificateID=%s; code=%s"
                % (cert_id, cert_result.code)
            )
            if cert_result.certificate is not None:
                rejected_cert = cert_result.certificate
                rejected_key = rejected_cert.public_key()
                key_bits = getattr(rejected_key, "key_size", "unknown")
                public_numbers = rejected_key.public_numbers() if hasattr(rejected_key, "public_numbers") else None
                exponent = getattr(public_numbers, "e", None)
                key_description = (
                    "RSA-%s/e=%s" % (key_bits, exponent)
                    if exponent is not None
                    else "%s (%s-bit)" % (type(rejected_key).__name__, key_bits)
                )
                steps.append(
                    "T1 certificate details: subject=%s; public_key=%s; validity=[%s, %s]"
                    % (
                        rejected_cert.subject.rfc4514_string(),
                        key_description,
                        rejected_cert.not_valid_before_utc.isoformat(),
                        rejected_cert.not_valid_after_utc.isoformat(),
                    )
                )
                if cert_result.code == "CERT_REVOKED" and crl is not None:
                    revoked_record = crl.get_revoked_certificate_by_serial_number(rejected_cert.serial_number)
                    if revoked_record is not None:
                        steps.append(
                            "T1 CRL revocation record: serial=%s; revoked_at=%s"
                            % (rejected_cert.serial_number, revoked_record.revocation_date_utc.isoformat())
                        )
            return finish(cert_result.code)
        cert = cert_result.certificate
        public_key = cert.public_key()
        steps.append(
            "T1 certificate details: subject=%s; public_key=RSA-%d/e=%d; validity=[%s, %s]"
            % (
                cert.subject.rfc4514_string(),
                public_key.key_size,
                public_key.public_numbers().e,
                cert.not_valid_before_utc.isoformat(),
                cert.not_valid_after_utc.isoformat(),
            )
        )
        steps.append("T1 certificate chain, validity, revocation and key policy: PASS")

        merchant_id = payload["MerchantID"]
        cert_identity = self.ca.merchant_identity(cert)
        registered = cert_id in self.registry.get(merchant_id, set())
        steps.append(
            "T1b identity comparison: payload.MerchantID=%s; certificate identity=%s; registered_for_MerchantID=%s"
            % (merchant_id, cert_identity, "YES" if registered else "NO")
        )
        if cert_identity != merchant_id or not registered:
            steps.append("T1b result: FAIL -> SIGNER_NOT_AUTHORIZED")
            return finish("SIGNER_NOT_AUTHORIZED")
        steps.append("T1b result: PASS; certificate identity is authorized for this MerchantID")

        if mode == "live":
            delta = (now - signed_at).total_seconds()
            steps.append(
                "T2 Timestamp comparison: signed_at=%s; verifier_now=%s; age=%+.0f s; allowed=[-%d, +%d] s"
                % (
                    format_timestamp(signed_at),
                    format_timestamp(now),
                    delta,
                    self.window_seconds,
                    self.window_seconds,
                )
            )
            if delta > self.window_seconds:
                steps.append("T2 result: FAIL, Timestamp is too old -> TIMESTAMP_TOO_OLD")
                return finish("TIMESTAMP_TOO_OLD")
            if delta < -self.window_seconds:
                steps.append("T2 result: FAIL, Timestamp is too far in the future -> TIMESTAMP_IN_FUTURE")
                return finish("TIMESTAMP_IN_FUTURE")
            steps.append("T2 result: PASS; Timestamp is within the allowed window")
            try:
                nonce_seen = self.replay_store.nonce_seen(
                    merchant_id,
                    payload["Nonce"],
                    now.timestamp(),
                )
                steps.append(
                    "T3 nonce lookup: MerchantID=%s; Nonce=%s; already_seen=%s"
                    % (merchant_id, payload["Nonce"], "YES" if nonce_seen else "NO")
                )
                if nonce_seen:
                    steps.append("T3 result: FAIL -> REPLAY_DETECTED")
                    return finish("REPLAY_DETECTED")
            except ReplayStoreUnavailable:
                steps.append("T3 nonce store unavailable: fail closed -> SERVICE_UNAVAILABLE")
                return finish("SERVICE_UNAVAILABLE")
            steps.append("T3 result: PASS; nonce is not present in replay store")
        else:
            steps.append("T2/T3 freshness and replay checks: SKIPPED (mode=postcheck)")

        try:
            canonical = canonical_json_bytes(payload)
        except CanonicalizationError as exc:
            steps.append("T4 canonicalization: failed (%s) -> MALFORMED" % exc)
            return finish("MALFORMED")
        canonical_text = canonical.decode("utf-8")
        steps.append(
            "T4 canonical JSON: %d UTF-8 bytes = %s"
            % (len(canonical), canonical_text)
        )
        computed_hash = sha256_hex(canonical)
        declared_hash = packet["MessageHash"]
        hashes_match = computed_hash == declared_hash
        steps.append(
            "T4 SHA-256 comparison: recalculated=%s; envelope MessageHash=%s; match=%s"
            % (computed_hash, declared_hash, "YES" if hashes_match else "NO")
        )
        if not hashes_match:
            steps.append("T4 result: FAIL -> INTEGRITY_VIOLATION")
            return finish("INTEGRITY_VIOLATION")
        steps.append("T4 result: PASS; payload matches its declared MessageHash")

        public_key = cert.public_key()
        signature = bytes.fromhex(packet["Signature"])
        signature_valid = verify(public_key, canonical, signature)
        steps.append(
            "T5 RSA-PSS/SHA-256 verification: public_key=RSA-%d/e=%d; signature=%d bytes; verifies=%s"
            % (
                public_key.key_size,
                public_key.public_numbers().e,
                len(signature),
                "YES" if signature_valid else "NO",
            )
        )
        if not signature_valid:
            steps.append("T5 result: FAIL -> SIGNATURE_INVALID")
            return finish("SIGNATURE_INVALID")
        steps.append("T5 result: PASS; signature matches the canonical payload")

        if mode == "live":
            steps.append(
                "T3 atomic reservation input: MerchantID=%s; Nonce=%s; MessageID=%s"
                % (merchant_id, payload["Nonce"], payload["MessageID"])
            )
            try:
                conflict = self.replay_store.consume(
                    merchant_id,
                    payload["Nonce"],
                    payload["MessageID"],
                    now.timestamp(),
                )
            except ReplayStoreUnavailable:
                steps.append("T3 atomic reservation: state store unavailable; fail closed -> SERVICE_UNAVAILABLE")
                return finish("SERVICE_UNAVAILABLE")
            if conflict:
                steps.append("T3 atomic reservation result: conflict=%s" % conflict)
                return finish(conflict)
            steps.append("T3 atomic reservation result: Nonce and MessageID stored successfully")

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
