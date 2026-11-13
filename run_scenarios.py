#!/usr/bin/env python3
"""Run KS-01..KS-12, six unit-level error-code checks, flow demo or benchmark."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import importlib
import io
import pkgutil
import platform
import statistics
import ssl
import time
from typing import Any

import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa

import kich_ban
from ca_service import DemoCA
from he_thong import FrozenClock, Proxy, create_environment
from kich_ban.common import print_packet_material
from rsa_crypto import canonical_json_bytes, generate_private_key, sign, verify

BASE_TIME = dt.datetime(2026, 9, 24, 8, 0, 0, tzinfo=dt.timezone.utc)


def load_scenarios() -> list[Any]:
    modules = []
    for item in pkgutil.iter_modules(kich_ban.__path__):
        if item.name.startswith("ks_"):
            modules.append(importlib.import_module("kich_ban." + item.name))
    return sorted(modules, key=lambda module: module.SO)


def run_unit_checks() -> bool:
    """Exercise the six additional decision codes from the report."""
    env = create_environment(clock=FrozenClock(BASE_TIME))
    checks: list[tuple[str, str]] = []

    packet = env.merchant.create_packet(message_id="UNIT-CERT-NOT-FOUND")
    packet["CertificateID"] = "sha256:" + "0" * 64
    checks.append(("CERT_NOT_FOUND", env.issuer.verify_packet(packet)))

    foreign_ca = DemoCA(env.clock.now)
    foreign_key = generate_private_key(2048)
    foreign_id, foreign_cert = foreign_ca.issue("MERCH-01", foreign_key.public_key())
    env.ca.certificates[foreign_id] = foreign_cert  # trust-store fault injection
    packet = env.merchant.create_packet(message_id="UNIT-CHAIN-INVALID")
    packet["CertificateID"] = foreign_id
    checks.append(("CHAIN_INVALID", env.issuer.verify_packet(packet)))

    now = env.clock.now()
    not_yet_key = generate_private_key(2048)
    not_yet_id, _ = env.ca.issue(
        "MERCH-01",
        not_yet_key.public_key(),
        not_before=now + dt.timedelta(hours=1),
        not_after=now + dt.timedelta(hours=2),
    )
    packet = env.merchant.create_packet(message_id="UNIT-NOT-YET-VALID")
    packet["CertificateID"] = not_yet_id
    checks.append(("CERT_NOT_YET_VALID", env.issuer.verify_packet(packet)))

    expired_key = generate_private_key(2048)
    expired_id, _ = env.ca.issue(
        "MERCH-01",
        expired_key.public_key(),
        not_before=now - dt.timedelta(hours=2),
        not_after=now - dt.timedelta(hours=1),
    )
    packet = env.merchant.create_packet(message_id="UNIT-CERT-EXPIRED")
    packet["CertificateID"] = expired_id
    checks.append(("CERT_EXPIRED", env.issuer.verify_packet(packet)))

    weak_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
    weak_id, _ = env.ca.issue("MERCH-01", weak_key.public_key())
    packet = env.merchant.create_packet(message_id="UNIT-WEAK-EXPONENT")
    packet["CertificateID"] = weak_id
    checks.append(("WEAK_EXPONENT", env.issuer.verify_packet(packet)))

    packet = env.merchant.create_packet(message_id="UNIT-SERVICE-UNAVAILABLE")
    env.issuer.replay_store.down = True  # fail-closed fault injection
    checks.append(("SERVICE_UNAVAILABLE", env.issuer.verify_packet(packet)))
    env.issuer.replay_store.down = False

    print("\nUNIT-LEVEL DECISION CHECKS")
    all_ok = True
    for expected, actual in checks:
        ok = expected == actual
        all_ok = all_ok and ok
        print("  expected=%-22s actual=%-22s %s" % (expected, actual, "PASS" if ok else "FAIL"))
    return all_ok


def run_flow() -> bool:
    """Print one full, successful sample from payload creation through verification."""
    env = create_environment(clock=FrozenClock(BASE_TIME))
    signed_packet = env.merchant.create_packet(message_id="FLOW-2026-0001")
    received_packet = Proxy.forward(signed_packet)
    trace: list[str] = []
    code = env.issuer.verify_packet(received_packet, trace=trace)

    print("\nMẪU CHI TIẾT LUỒNG GIAO DỊCH G1–G8")
    print("[G1] Khởi tạo Demo CA, Merchant và Issuer.")
    print("[G2–G3] Merchant tạo payload rồi chuẩn hóa, băm và ký:")
    print_packet_material("Gói Merchant/Signer tạo:", signed_packet)
    print(
        "[G4] Proxy chuyển tiếp nguyên gói: %s"
        % ("không thay đổi payload/hash/chữ ký" if received_packet == signed_packet else "gói đã thay đổi")
    )
    print("[G5] Issuer nhận gói và kiểm tra T0–T5:")
    for line in trace:
        print("  %s" % line)
    print("[G6] Quyết định Issuer: %s" % code)
    print("[G7] Audit head: %s" % env.issuer.audit_log.head)
    print("[G8] Kỳ vọng SIGNATURE_VALID: %s" % ("ĐẠT" if code == "SIGNATURE_VALID" else "KHÔNG ĐẠT"))
    return code == "SIGNATURE_VALID" and received_packet == signed_packet


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = max(1, int((len(ordered) * fraction) + 0.999999))
    return ordered[rank - 1]


def run_benchmark(iterations: int = 300) -> bool:
    """Microbenchmark crypto primitives; not a production throughput test."""
    payload = {
        "Amount": 150000,
        "CardToken": "tok_" + "9" * 32,
        "Currency": "VND",
        "MerchantID": "MERCH-01",
        "MessageID": "BENCH-2026-0001",
        "Nonce": "0" * 32,
        "Timestamp": "2026-09-24T08:00:00Z",
    }
    message = canonical_json_bytes(payload)
    print("BENCHMARK: %d-byte canonical payload, serial primitive timings" % len(message))
    print("Python %s | cryptography %s | OpenSSL %s | %s" % (
        platform.python_version(), cryptography.__version__, ssl.OPENSSL_VERSION, platform.platform()
    ))
    for bits in (2048, 3072):
        key = generate_private_key(bits)
        signature = sign(key, message)
        # Warm-up before collecting samples.
        for _ in range(30):
            sign(key, message)
            verify(key.public_key(), message, signature)
        sign_ms: list[float] = []
        verify_ms: list[float] = []
        canonical_ms: list[float] = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            sign(key, message)
            sign_ms.append((time.perf_counter_ns() - start) / 1_000_000)
            start = time.perf_counter_ns()
            verify(key.public_key(), message, signature)
            verify_ms.append((time.perf_counter_ns() - start) / 1_000_000)
            start = time.perf_counter_ns()
            canonical_json_bytes(payload)
            canonical_ms.append((time.perf_counter_ns() - start) / 1_000_000)
        keygen_ms: list[float] = []
        for _ in range(10):
            start = time.perf_counter_ns()
            generate_private_key(bits)
            keygen_ms.append((time.perf_counter_ns() - start) / 1_000_000)
        sign_mean = statistics.mean(sign_ms)
        verify_mean = statistics.mean(verify_ms)
        print(
            "RSA-%d | sign mean %.3f ms p95 %.3f | verify mean %.3f ms p95 %.3f | "
            "canonicalize+encode mean %.4f ms | keygen mean(10) %.1f ms | signature %d bytes"
            % (
                bits,
                sign_mean,
                percentile(sign_ms, 0.95),
                verify_mean,
                percentile(verify_ms, 0.95),
                statistics.mean(canonical_ms),
                statistics.mean(keygen_ms),
                len(signature),
            )
        )
        print(
            "  reciprocal-of-mean estimate (not measured service throughput): "
            "%.0f signs/s, %.0f verifies/s"
            % (1000.0 / sign_mean, 1000.0 / verify_mean)
        )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ks", type=int, help="run one end-to-end scenario, 1..12")
    parser.add_argument("--flow", action="store_true", help="print one successful G1-G8 flow")
    parser.add_argument("--bench", action="store_true", help="benchmark RSA primitives")
    parser.add_argument("--no-unit", action="store_true", help="skip six unit-level checks in full run")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show full payloads, hashes, signatures and T0-T5 traces",
    )
    args = parser.parse_args()

    if args.flow:
        return 0 if run_flow() else 1
    if args.bench:
        run_benchmark()
        return 0

    scenarios = load_scenarios()
    if args.ks is not None:
        if args.ks < 1 or args.ks > 12:
            parser.error("--ks must be in the range 1..12")
        env = create_environment(clock=FrozenClock(BASE_TIME))
        chosen = next(module for module in scenarios if module.SO == args.ks)
        # KS-02 and KS-06 reuse the original KS-01 nonce; KS-09 verifies its
        # stored signature. Seed the necessary fixture first.
        if args.ks in {2, 6, 9}:
            # Seed KS-01 without printing it as an extra scenario in this run.
            with contextlib.redirect_stdout(io.StringIO()):
                scenarios[0].chay(env)
        ok = chosen.chay(env, verbose=args.verbose)
        return 0 if ok else 1

    flow_ok = run_flow()
    print("\nKẾT QUẢ CÁC KỊCH BẢN KS")
    env = create_environment(clock=FrozenClock(BASE_TIME))
    results = [module.chay(env, verbose=args.verbose) for module in scenarios]
    print("\nEND-TO-END: %d/%d passed" % (sum(results), len(results)))
    unit_ok = True if args.no_unit else run_unit_checks()
    return 0 if flow_ok and all(results) and unit_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
