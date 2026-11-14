import concurrent.futures
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from ca_service import CRL_TTL
from he_thong import FrozenClock, create_environment
from nonce_store import InMemoryReplayStore, NONCE_TTL_SECONDS
from run_scenarios import BASE_TIME, load_scenarios, run_flow, run_unit_checks


def make_env():
    return create_environment(clock=FrozenClock(BASE_TIME))


def test_verify_packet_strictly_parses_raw_json_at_ingress():
    env = make_env()
    packet = env.merchant.create_packet(message_id="RAW-JSON-001")
    raw = json.dumps(packet, ensure_ascii=False, separators=(",", ":"))
    trace = []

    assert env.issuer.verify_packet(raw, trace=trace) == "SIGNATURE_VALID"
    assert trace[0].startswith("T0 JSON parsing: PASS")


def test_verify_packet_rejects_ambiguous_non_finite_and_oversized_json():
    env = make_env()
    invalid_inputs = (
        '{"payload":{},"payload":{}}',
        '{"Amount":1.5}',
        '{"Amount":NaN}',
        " " * 16_385,
    )

    for raw in invalid_inputs:
        trace = []
        assert env.issuer.verify_packet(raw, trace=trace) == "MALFORMED"
        assert trace[0].startswith("T0 JSON parsing:")


def test_all_twelve_report_scenarios_pass():
    env = make_env()
    results = [module.chay(env) for module in load_scenarios()]
    assert len(results) == 12
    assert all(results)


def test_ks05_delayed_packet_is_rejected_by_timestamp_and_restores_clock(capsys):
    env = make_env()
    scenario = next(module for module in load_scenarios() if module.SO == 5)

    assert scenario.chay(env, verbose=True)
    assert env.clock.now() == BASE_TIME
    output = capsys.readouterr().out
    assert "Proxy giữ nguyên gói đã ký" in output
    assert "Gói đưa vào Issuer: giữ nguyên như gói đã ký." in output
    assert "TIMESTAMP_TOO_OLD" in output


def test_scenario_report_shows_data_representation_and_failure_stage(capsys):
    env = make_env()
    scenario = next(module for module in load_scenarios() if module.SO == 3)

    assert scenario.chay(env, verbose=True)
    output = capsys.readouterr().out

    assert "Canonical JSON UTF-8" in output
    assert "SHA-256(canonical JSON)" in output
    assert "Signature RSA-PSS/SHA-256" in output
    assert "payload.Amount: 150000 → 1500000" in output
    assert "T4 SHA-256 comparison:" in output
    assert "match=NO" in output
    assert "T4 result: FAIL -> INTEGRITY_VIOLATION" in output
    assert "T5" not in output


def test_compact_report_prints_only_the_scenario_result(capsys):
    env = make_env()
    scenario = next(module for module in load_scenarios() if module.SO == 3)

    assert scenario.chay(env)
    output = capsys.readouterr().out.strip()

    assert output.startswith("KS-03 · Proxy sửa Amount")
    assert "INTEGRITY_VIOLATION" in output
    assert "ĐẠT" in output
    assert "payload" not in output
    assert "SHA-256" not in output
    assert "T4" not in output
    assert len(output.splitlines()) == 1


def test_flow_demo_prints_full_transform_sample(capsys):
    assert run_flow()
    output = capsys.readouterr().out

    assert "Payload JSON (dữ liệu có thể đọc)" in output
    assert "Canonical JSON UTF-8" in output
    assert "SHA-256(canonical JSON)" in output
    assert "Signature RSA-PSS/SHA-256" in output
    assert "T0 envelope fields:" in output
    assert "T5 result: PASS" in output
    assert "payload không bị mã hóa" in output


def test_report_shows_missing_envelope_field_and_stops_at_t0(capsys):
    env = make_env()
    scenario = next(module for module in load_scenarios() if module.SO == 11)

    assert scenario.chay(env, verbose=True)
    output = capsys.readouterr().out

    assert "missing=[MessageHash]" in output
    assert "T0 envelope result: missing=[MessageHash]" in output
    assert "T1 inputs:" not in output
    assert "Issuer quyết định: MALFORMED | Kịch bản: ĐẠT" in output


def test_six_additional_decision_codes_pass():
    assert run_unit_checks()


def test_same_message_id_with_fresh_nonce_is_rejected_as_duplicate():
    env = make_env()
    first = env.merchant.create_packet(message_id="IDEMPOTENCY-001")
    second = env.merchant.create_packet(message_id="IDEMPOTENCY-001")
    assert first["payload"]["Nonce"] != second["payload"]["Nonce"]
    assert env.issuer.verify_packet(first) == "SIGNATURE_VALID"
    assert env.issuer.verify_packet(second) == "DUPLICATE_MESSAGE"


def test_concurrent_same_message_id_with_distinct_nonces_has_one_success():
    env = make_env()
    packets = [
        env.merchant.create_packet(message_id="CONCURRENT-IDEMPOTENCY-001")
        for _ in range(8)
    ]
    assert len({packet["payload"]["Nonce"] for packet in packets}) == len(packets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(env.issuer.verify_packet, packets))

    assert results.count("SIGNATURE_VALID") == 1
    assert results.count("DUPLICATE_MESSAGE") == 7


def test_concurrent_duplicate_submission_has_one_success():
    env = make_env()
    packet = env.merchant.create_packet(message_id="CONCURRENT-001")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: env.issuer.verify_packet(packet), range(8)))
    assert results.count("SIGNATURE_VALID") == 1
    assert results.count("REPLAY_DETECTED") == 7


def test_future_timestamp_outside_window_is_rejected():
    env = make_env()
    packet = env.merchant.create_packet(
        message_id="FUTURE-001",
        timestamp=BASE_TIME + dt.timedelta(minutes=6),
    )
    assert env.issuer.verify_packet(packet) == "TIMESTAMP_IN_FUTURE"


def test_nonce_ttl_covers_inclusive_timestamp_window_boundary():
    env = make_env()
    packet = env.merchant.create_packet(
        message_id="NONCE-BOUNDARY-001",
        timestamp=BASE_TIME + dt.timedelta(seconds=env.issuer.window_seconds),
    )

    assert NONCE_TTL_SECONDS == 660
    assert env.issuer.replay_store.nonce_ttl > 2 * env.issuer.window_seconds
    assert env.issuer.verify_packet(packet) == "SIGNATURE_VALID"

    # Timestamp remains valid at the inclusive +300-second boundary, but the
    # nonce must still be present and reject the same signed packet at +600 s.
    env.clock.advance(dt.timedelta(seconds=2 * env.issuer.window_seconds))
    assert env.issuer.verify_packet(packet) == "REPLAY_DETECTED"


def test_issuer_rejects_replay_store_with_too_short_nonce_ttl():
    short_ttl_store = InMemoryReplayStore(nonce_ttl=600)
    with pytest.raises(ValueError, match="nonce_ttl must be at least 660 seconds"):
        create_environment(clock=FrozenClock(BASE_TIME), replay_store=short_ttl_store)


def test_certificate_without_digital_signature_usage_is_rejected():
    env = make_env()
    now = BASE_TIME
    issued_key_usage = env.merchant.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    issued_san = env.merchant.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert issued_key_usage.digital_signature
    assert issued_san.get_values_for_type(x509.UniformResourceIdentifier) == [
        "urn:merchant:%s" % env.merchant.merchant_id
    ]

    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, env.merchant.merchant_id)]))
        .issuer_name(env.ca.root_cert.subject)
        .public_key(env.merchant.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,
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
                [x509.UniformResourceIdentifier("urn:merchant:%s" % env.merchant.merchant_id)]
            ),
            critical=False,
        )
        .sign(env.ca.root_key, hashes.SHA256())
    )
    cert_id = env.ca.certificate_id(certificate)
    env.ca.certificates[cert_id] = certificate
    env.issuer.register_merchant(env.merchant.merchant_id, cert_id)
    packet = env.merchant.create_packet(message_id="BAD-KEY-USAGE-001")
    packet["CertificateID"] = cert_id

    assert env.issuer.verify_packet(packet) == "CERT_POLICY_INVALID"


def test_untrusted_backdated_timestamp_cannot_override_revocation():
    env = make_env()
    packet = env.merchant.create_packet(
        message_id="BACKDATED-REVOKED-001",
        timestamp=BASE_TIME - dt.timedelta(seconds=10),
    )
    env.ca.revoke(env.merchant.certificate_id, when=BASE_TIME - dt.timedelta(seconds=5))
    assert env.issuer.verify_packet(packet, mode="postcheck") == "CERT_REVOKED"


def test_demo_ca_renews_crl_when_next_update_is_reached():
    env = make_env()
    assert CRL_TTL == dt.timedelta(hours=1)
    initial_crl = env.ca.get_crl()

    env.clock.advance(CRL_TTL)
    refreshed_crl = env.ca.get_crl()

    assert refreshed_crl.last_update_utc == env.clock.now()
    assert refreshed_crl.next_update_utc > initial_crl.next_update_utc


def test_expired_crl_cache_fails_closed_when_ca_is_unavailable():
    env = make_env()
    packet = env.merchant.create_packet(message_id="CRL-CACHE-OUTAGE")
    assert env.issuer.verify_packet(packet) == "SIGNATURE_VALID"

    env.ca.down = True
    env.clock.advance(CRL_TTL + dt.timedelta(seconds=1))
    packet_after_expiry = env.merchant.create_packet(message_id="CRL-CACHE-EXPIRED")
    assert env.issuer.verify_packet(packet_after_expiry) == "SERVICE_UNAVAILABLE"


def test_replay_store_unavailable_fails_closed():
    env = make_env()
    packet = env.merchant.create_packet(message_id="REPLAY-STORE-OUTAGE")
    trace = []
    env.issuer.replay_store.down = True
    try:
        assert env.issuer.verify_packet(packet, trace=trace) == "SERVICE_UNAVAILABLE"
    finally:
        env.issuer.replay_store.down = False

    assert any("nonce store unavailable" in step for step in trace)


def test_oversized_signature_is_malformed_before_crypto_processing():
    env = make_env()
    packet = env.merchant.create_packet(message_id="OVERSIZED-SIG")
    packet["Signature"] = "00" * 1025
    assert env.issuer.verify_packet(packet) == "MALFORMED"


def test_invalid_nonce_length_is_malformed():
    env = make_env()
    packet = env.merchant.make_payload(message_id="BAD-NONCE", nonce="abcd")
    # Sign the malformed payload through the low-level API only to prove the
    # verifier rejects it at the schema boundary.
    from rsa_crypto import canonical_json_bytes, sha256_hex, sign
    packet = {
        "payload": packet,
        "MessageHash": sha256_hex(canonical_json_bytes(packet)),
        "Signature": sign(env.merchant.private_key, canonical_json_bytes(packet)).hex(),
        "CertificateID": env.merchant.certificate_id,
    }
    assert env.issuer.verify_packet(packet) == "MALFORMED"
