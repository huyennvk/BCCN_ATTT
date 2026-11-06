"""Small in-process X.509 CA used for demonstrations and tests only.

This is not a production PKI: it has one directly trusted root, ephemeral
keys, no durable key-management lifecycle, no OCSP, and no path building.
The CRL in this version is a real signed X.509 CRL (unlike a dictionary mock),
but production deployments should use a fully managed CA/validation service.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from rsa_crypto import MIN_KEY_BITS, PUBLIC_EXPONENT, generate_private_key

UTC = dt.timezone.utc
# Demonstration freshness bound; production CRL cadence is set by the real CA.
CRL_TTL = dt.timedelta(hours=1)


class CAUnavailable(ConnectionError):
    """The simulated certificate authority is unavailable."""


@dataclass(frozen=True)
class CertificateResult:
    code: str
    certificate: x509.Certificate | None = None


class DemoCA:
    """Ephemeral root CA and certificate/revocation registry for the prototype."""

    def __init__(
        self,
        clock: Callable[[], dt.datetime],
        root_key_size: int = 3072,
        validity: dt.timedelta = dt.timedelta(days=365 * 4),
    ) -> None:
        self.clock = clock
        self.root_key = generate_private_key(root_key_size)
        now = self._aware(clock())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BCCN-ATTT-DEMO-ROOT")])
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + validity)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()), critical=False)
            .sign(self.root_key, hashes.SHA256())
        )
        self.certificates: dict[str, x509.Certificate] = {}
        self.revoked: dict[int, tuple[dt.datetime, x509.ReasonFlags]] = {}
        self.crl_number = 0
        self.down = False
        self._crl = self._build_crl(now)

    @staticmethod
    def _aware(value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None:
            raise ValueError("all timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def certificate_id(cert: x509.Certificate) -> str:
        der = cert.public_bytes(serialization.Encoding.DER)
        return "sha256:" + hashlib.sha256(der).hexdigest().upper()

    def issue(
        self,
        merchant_id: str,
        public_key: rsa.RSAPublicKey,
        *,
        not_before: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
    ) -> tuple[str, x509.Certificate]:
        now = self._aware(self.clock())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, merchant_id)])
        start = self._aware(not_before) if not_before else now - dt.timedelta(days=1)
        end = self._aware(not_after) if not_after else now + dt.timedelta(days=30)
        if end <= start:
            raise ValueError("certificate not_after must be later than not_before")
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("urn:merchant:%s" % merchant_id)]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
            .sign(self.root_key, hashes.SHA256())
        )
        cert_id = self.certificate_id(cert)
        self.certificates[cert_id] = cert
        return cert_id, cert

    def revoke(
        self,
        cert_id: str,
        when: dt.datetime | None = None,
        reason: x509.ReasonFlags = x509.ReasonFlags.key_compromise,
    ) -> None:
        cert = self.certificates.get(cert_id)
        if cert is None:
            raise KeyError("unknown certificate id")
        at = self._aware(when) if when else self._aware(self.clock())
        self.revoked[cert.serial_number] = (at, reason)
        self._crl = self._build_crl(self._aware(self.clock()))

    def unrevoke(self, cert_id: str) -> None:
        """Remove a test revocation and publish a fresh CRL snapshot."""
        cert = self.certificates.get(cert_id)
        if cert is None:
            raise KeyError("unknown certificate id")
        self.revoked.pop(cert.serial_number, None)
        self._crl = self._build_crl(self._aware(self.clock()))

    def _build_crl(self, now: dt.datetime) -> x509.CertificateRevocationList:
        self.crl_number += 1
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.root_cert.subject)
            .last_update(now)
            .next_update(now + CRL_TTL)
            .add_extension(x509.CRLNumber(self.crl_number), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        for serial, (revoked_at, reason) in sorted(self.revoked.items()):
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        return builder.sign(self.root_key, hashes.SHA256())

    def get_crl(self) -> x509.CertificateRevocationList:
        if self.down:
            raise CAUnavailable("CA unavailable")
        now = self._aware(self.clock())
        if self._crl.next_update_utc <= now:
            self._crl = self._build_crl(now)
        return self._crl

    def get_certificate(self, cert_id: str) -> x509.Certificate | None:
        return self.certificates.get(cert_id)

    def _verify_crl(self, crl: x509.CertificateRevocationList, now: dt.datetime) -> bool:
        try:
            if crl.issuer != self.root_cert.subject:
                return False
            if crl.last_update_utc > now or crl.next_update_utc < now:
                return False
            self.root_key.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False

    def validate_certificate(
        self,
        cert_id: str,
        at: dt.datetime,
        crl: x509.CertificateRevocationList | None,
        *,
        revocation_time: dt.datetime | None = None,
        require_current_validity: bool = False,
    ) -> CertificateResult:
        """Validate a directly-issued leaf certificate.

        ``at`` is the signed timestamp used for the historical validity check.
        Revocation is checked against the verifier's current time by default;
        an untrusted Merchant timestamp must not undo a revocation. Live checks
        additionally require the leaf to remain valid now.
        """
        if self.down and crl is None:
            return CertificateResult("SERVICE_UNAVAILABLE")
        cert = self.certificates.get(cert_id)
        if cert is None:
            return CertificateResult("CERT_NOT_FOUND")
        if self.certificate_id(cert) != cert_id:
            return CertificateResult("CHAIN_INVALID", cert)
        at = self._aware(at)
        now = self._aware(self.clock())
        revocation_cutoff = self._aware(revocation_time) if revocation_time else now
        try:
            cert.verify_directly_issued_by(self.root_cert)
        except Exception:
            return CertificateResult("CHAIN_INVALID", cert)

        if at < self.root_cert.not_valid_before_utc or at > self.root_cert.not_valid_after_utc:
            return CertificateResult("CHAIN_INVALID", cert)
        if at < cert.not_valid_before_utc:
            return CertificateResult("CERT_NOT_YET_VALID", cert)
        if at > cert.not_valid_after_utc:
            return CertificateResult("CERT_EXPIRED", cert)
        if require_current_validity:
            if now < self.root_cert.not_valid_before_utc or now > self.root_cert.not_valid_after_utc:
                return CertificateResult("CHAIN_INVALID", cert)
            if now < cert.not_valid_before_utc:
                return CertificateResult("CERT_NOT_YET_VALID", cert)
            if now > cert.not_valid_after_utc:
                return CertificateResult("CERT_EXPIRED", cert)

        if crl is None or not self._verify_crl(crl, now):
            return CertificateResult("SERVICE_UNAVAILABLE", cert)
        revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked_entry is not None and revoked_entry.revocation_date_utc <= revocation_cutoff:
            return CertificateResult("CERT_REVOKED", cert)

        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not key_usage.digital_signature:
                return CertificateResult("CERT_POLICY_INVALID", cert)
        except x509.ExtensionNotFound:
            return CertificateResult("CERT_POLICY_INVALID", cert)

        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            return CertificateResult("KEY_TOO_WEAK", cert)
        if public_key.key_size < MIN_KEY_BITS:
            return CertificateResult("KEY_TOO_WEAK", cert)
        if public_key.public_numbers().e != PUBLIC_EXPONENT:
            return CertificateResult("WEAK_EXPONENT", cert)
        return CertificateResult("OK", cert)

    @staticmethod
    def merchant_identity(cert: x509.Certificate) -> str | None:
        try:
            uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.UniformResourceIdentifier
            )
        except x509.ExtensionNotFound:
            return None
        prefix = "urn:merchant:"
        if len(uris) != 1 or not uris[0].startswith(prefix):
            return None
        return uris[0][len(prefix):]
