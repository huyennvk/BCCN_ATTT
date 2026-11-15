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
from kich_ban.common import format_layer_path, print_flow_log
from rsa_crypto import canonical_json_bytes, generate_private_key, sign, verify

BASE_TIME = dt.datetime(2026, 9, 24, 8, 0, 0, tzinfo=dt.timezone.utc)


def load_scenarios() -> list[Any]:
    modules = []
    for item in pkgutil.iter_modules(kich_ban.__path__):
        if item.name.startswith("ks_"):
            modules.append(importlib.import_module("kich_ban." + item.name))
    return sorted(modules, key=lambda module: module.SO)


def run_unit_checks(*, detailed: bool = True) -> bool:
    """Run the six additional decision-code checks.

    The CLI full-suite mode uses compact rows; detailed mode is retained for
    direct diagnostic runs and prints only safe layer/status information.
    """
    env = create_environment(clock=FrozenClock(BASE_TIME))
    checks: list[tuple[str, str, list[str]]] = []

    def record(expected: str, packet: dict[str, Any]) -> None:
        trace: list[str] = []
        actual = env.issuer.verify_packet(packet, trace=trace)
        checks.append((expected, actual, trace))

    packet = env.merchant.create_packet(message_id="UNIT-CERT-NOT-FOUND")
    packet["CertificateID"] = "sha256:" + "0" * 64
    record("CERT_NOT_FOUND", packet)

    foreign_ca = DemoCA(env.clock.now)
    foreign_key = generate_private_key(2048)
    foreign_id, foreign_cert = foreign_ca.issue("MERCH-01", foreign_key.public_key())
    env.ca.certificates[foreign_id] = foreign_cert  # trust-store fault injection
    packet = env.merchant.create_packet(message_id="UNIT-CHAIN-INVALID")
    packet["CertificateID"] = foreign_id
    record("CHAIN_INVALID", packet)

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
    record("CERT_NOT_YET_VALID", packet)

    expired_key = generate_private_key(2048)
    expired_id, _ = env.ca.issue(
        "MERCH-01",
        expired_key.public_key(),
        not_before=now - dt.timedelta(hours=2),
        not_after=now - dt.timedelta(hours=1),
    )
    packet = env.merchant.create_packet(message_id="UNIT-CERT-EXPIRED")
    packet["CertificateID"] = expired_id
    record("CERT_EXPIRED", packet)

    weak_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
    weak_id, _ = env.ca.issue("MERCH-01", weak_key.public_key())
    packet = env.merchant.create_packet(message_id="UNIT-WEAK-EXPONENT")
    packet["CertificateID"] = weak_id
    record("WEAK_EXPONENT", packet)

    packet = env.merchant.create_packet(message_id="UNIT-SERVICE-UNAVAILABLE")
    env.issuer.replay_store.down = True  # fail-closed fault injection
    try:
        record("SERVICE_UNAVAILABLE", packet)
    finally:
        env.issuer.replay_store.down = False

    all_ok = True
    for index, (expected, actual, trace) in enumerate(checks, start=1):
        ok = expected == actual
        all_ok = all_ok and ok
        if detailed:
            print(
                "UNIT %s %s | %s"
                % (expected, "PASS" if ok else "FAIL", format_layer_path(actual, trace))
            )
        elif ok:
            print("NGOÀI LỀ-%02d | PASS | %s" % (index, expected))
        else:
            print(
                "NGOÀI LỀ-%02d | FAIL | expected=%s actual=%s"
                % (index, expected, actual)
            )
    passed_count = sum(expected == actual for expected, actual, _ in checks)
    summary_label = "UNIT CHECKS" if detailed else "NGOÀI LỀ"
    print(
        "%s %s %d/%d"
        % (summary_label, "PASS" if all_ok else "FAIL", passed_count, len(checks))
    )
    return all_ok


def run_flow() -> bool:
    """Run one valid G-stage flow and show Issuer's T-layer results."""
    env = create_environment(clock=FrozenClock(BASE_TIME))
    signed_packet = env.merchant.create_packet(message_id="FLOW-2026-0001")
    received_packet = Proxy.forward(signed_packet)
    trace: list[str] = []
    code = env.issuer.verify_packet(received_packet, trace=trace)
    ok = code == "SIGNATURE_VALID" and received_packet == signed_packet
    reported_ok = print_flow_log("FLOW", code, "SIGNATURE_VALID", trace)
    return ok and reported_ok


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


def _run_scenario_quietly(module: Any, env: Any) -> tuple[bool, str, str | None]:
    """Run a scenario while collecting its safe G-log for the full-run summary."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        success = bool(module.chay(env))

    decision_prefix = "[Phán quyết] G6: "
    event_prefix = "[Sự kiện] "
    decision = next(
        (line[len(decision_prefix):] for line in captured.getvalue().splitlines()
         if line.startswith(decision_prefix)),
        "UNKNOWN",
    )
    event_note = next(
        (line[len(event_prefix):] for line in captured.getvalue().splitlines()
         if line.startswith(event_prefix)),
        None,
    )
    return success and decision != "UNKNOWN", decision, event_note


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ks", type=int, help="run one group-numbered end-to-end scenario, 1..12"
    )
    parser.add_argument(
        "--flow", action="store_true", help="run one valid flow; print only layer statuses"
    )
    parser.add_argument("--bench", action="store_true", help="benchmark RSA primitives")
    parser.add_argument(
        "--verbose", action="store_true",
        help="kept for compatibility; does not expand the full-run summary or expose packet data",
    )
    parser.add_argument(
        "--no-unit", action="store_true", help="skip six unit-level checks in full run"
    )
    args = parser.parse_args()
    # --verbose does not expand the full-suite summary; --ks and --flow remain redacted G-logs.

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
        # KS-02 verifies KS-01's stored signature; KS-03 and KS-05 reuse its nonce.
        # Seed the necessary fixture without extra output.
        if args.ks in {2, 3, 5}:
            with contextlib.redirect_stdout(io.StringIO()):
                scenarios[0].chay(env)
        return 0 if chosen.chay(env) else 1

    env = create_environment(clock=FrozenClock(BASE_TIME))
    print("TÓM TẮT TOÀN BỘ")
    print("KỊCH BẢN KS")
    scenario_results: list[bool] = []
    for module in scenarios:
        ok, actual, event_note = _run_scenario_quietly(module, env)
        expected = module.KY_VONG
        ok = ok and actual == expected
        scenario_results.append(ok)
        row = "KS-%02d | %s | %s" % (
            module.SO,
            "PASS" if ok else "FAIL",
            actual,
        )
        if not ok:
            row += " | expected=%s" % expected
        if event_note:
            row += " | %s" % event_note
        print(row)

    end_to_end_ok = all(scenario_results)
    print(
        "KS TỔNG %s %d/%d"
        % ("PASS" if end_to_end_ok else "FAIL", sum(scenario_results), len(scenario_results))
    )

    if args.no_unit:
        unit_ok = True
        print("NGOÀI LỀ | SKIP (--no-unit)")
    else:
        unit_ok = run_unit_checks(detailed=False)
    overall_ok = end_to_end_ok and unit_ok
    print("OVERALL %s" % ("PASS" if overall_ok else "FAIL"))
    return 0 if overall_ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
