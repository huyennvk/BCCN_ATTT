#!/usr/bin/env python3
"""Standalone microbenchmark for the project's RSA-PSS/SHA-256 primitives.

Run from the repository root with the project's requirements installed:
    python benchmark_crypto.py

This is a serial, in-process microbenchmark, not a production throughput test.
"""
from __future__ import annotations

import argparse
import os
import platform
import statistics
import ssl
import sys
import time
from typing import Any, Callable

import cryptography

from rsa_crypto import canonical_json_bytes, generate_private_key, sha256_hex, sign, verify

DEFAULT_ITERATIONS = 300
DEFAULT_WARMUP = 30
DEFAULT_KEYGEN_SAMPLES = 10
DEFAULT_HASH_OPS_PER_SAMPLE = 100
KEY_SIZES = (2048, 3072)

# Keep this representative input identical to run_scenarios.py --bench.
PAYLOAD = {
    "Amount": 150000,
    "CardToken": "tok_" + "9" * 32,
    "Currency": "VND",
    "MerchantID": "MERCH-01",
    "MessageID": "BENCH-2026-0001",
    "Nonce": "0" * 32,
    "Timestamp": "2026-09-24T08:00:00Z",
}


def percentile(values: list[float], fraction: float) -> float:
    """Return the nearest-rank percentile used by the existing runner."""
    if not values:
        raise ValueError("cannot calculate a percentile from no samples")
    ordered = sorted(values)
    rank = max(1, int((len(ordered) * fraction) + 0.999999))
    return ordered[rank - 1]


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed


def _measure_ms(
    operation: Callable[[], Any],
    *,
    samples: int,
    operations_per_sample: int = 1,
    validate: Callable[[Any], bool] | None = None,
) -> list[float]:
    """Measure per-operation milliseconds, batching tiny operations when needed."""
    timings: list[float] = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        result = None
        for _ in range(operations_per_sample):
            result = operation()
        elapsed_ns = time.perf_counter_ns() - start
        if validate is not None and not validate(result):
            raise RuntimeError("benchmark operation returned an unexpected result")
        timings.append(elapsed_ns / operations_per_sample / 1_000_000)
    return timings


def _cpu_description() -> str:
    processor = platform.processor().strip()
    if processor:
        return processor
    # platform.processor() is often empty on Linux containers.
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as cpuinfo:
            for line in cpuinfo:
                if line.lower().startswith(("model name", "hardware")):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _allowed_cpu_count() -> int | None:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return None


def print_environment() -> None:
    affinity_count = _allowed_cpu_count()
    cpu_counts = "host logical CPUs: %s" % (os.cpu_count() or "unknown")
    if affinity_count is not None:
        cpu_counts += " | CPUs allowed to process: %d" % affinity_count

    print("Environment:")
    print("  Python: %s | executable: %s" % (platform.python_version(), sys.executable))
    print("  cryptography: %s | %s" % (cryptography.__version__, ssl.OPENSSL_VERSION))
    try:
        os_name = platform.freedesktop_os_release().get("PRETTY_NAME", platform.system())
    except (AttributeError, OSError):
        os_name = platform.system()
    print(
        "  Platform: %s | kernel: %s | machine: %s"
        % (os_name, platform.release(), platform.machine())
    )
    print("  CPU: %s | %s" % (_cpu_description(), cpu_counts))


def run_benchmark(args: argparse.Namespace) -> bool:
    message = canonical_json_bytes(PAYLOAD)
    expected_digest = sha256_hex(message)
    print_environment()
    print(
        "Benchmark: %d-byte canonical payload | iterations=%d | "
        "warm-up=%d | key-generation samples=%d | serial, one process"
        % (len(message), args.iterations, args.warmup, args.keygen_samples)
    )
    print(
        "SHA-256 timing uses %d calls per sample to reduce timer overhead."
        % args.hash_ops_per_sample
    )

    def canonicalize_once() -> bytes:
        return canonical_json_bytes(PAYLOAD)

    def hash_once() -> str:
        return sha256_hex(message)

    for _ in range(args.warmup):
        if canonicalize_once() != message:
            raise RuntimeError("warm-up canonicalization result was unexpected")
    for _ in range(args.warmup * args.hash_ops_per_sample):
        if hash_once() != expected_digest:
            raise RuntimeError("warm-up SHA-256 result was unexpected")

    canonical_ms = _measure_ms(
        canonicalize_once,
        samples=args.iterations,
        validate=lambda result: result == message,
    )
    hash_ms = _measure_ms(
        hash_once,
        samples=args.iterations,
        operations_per_sample=args.hash_ops_per_sample,
        validate=lambda result: result == expected_digest,
    )
    print(
        "Payload operations | SHA-256 mean %.4f ms/op p95 %.4f | "
        "canonicalize+encode mean %.4f ms p95 %.4f"
        % (
            statistics.mean(hash_ms),
            percentile(hash_ms, 0.95),
            statistics.mean(canonical_ms),
            percentile(canonical_ms, 0.95),
        )
    )

    for bits in args.sizes:
        private_key = generate_private_key(bits)
        public_key = private_key.public_key()
        signature = sign(private_key, message)
        if not verify(public_key, message, signature):
            raise RuntimeError("initial signature verification failed")

        for _ in range(args.warmup):
            sign(private_key, message)
            if not verify(public_key, message, signature):
                raise RuntimeError("warm-up signature verification failed")

        # Keep sign and verify interleaved in one timed loop, matching the
        # sampling order of run_scenarios.py --bench.
        sign_ms: list[float] = []
        verify_ms: list[float] = []
        for _ in range(args.iterations):
            start = time.perf_counter_ns()
            measured_signature = sign(private_key, message)
            sign_ms.append((time.perf_counter_ns() - start) / 1_000_000)
            if len(measured_signature) != bits // 8:
                raise RuntimeError("signature length was unexpected")

            start = time.perf_counter_ns()
            verified = verify(public_key, message, signature)
            verify_ms.append((time.perf_counter_ns() - start) / 1_000_000)
            if not verified:
                raise RuntimeError("timed signature verification failed")

        keygen_ms = _measure_ms(
            lambda: generate_private_key(bits),
            samples=args.keygen_samples,
        )
        sign_mean = statistics.mean(sign_ms)
        verify_mean = statistics.mean(verify_ms)
        print(
            "RSA-%d | sign mean %.3f ms p95 %.3f | "
            "verify mean %.3f ms p95 %.3f | keygen mean(%d) %.1f ms | "
            "signature %d bytes"
            % (
                bits,
                sign_mean,
                percentile(sign_ms, 0.95),
                verify_mean,
                percentile(verify_ms, 0.95),
                args.keygen_samples,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run an independent serial microbenchmark of the project's crypto primitives."
    )
    parser.add_argument(
        "--iterations",
        type=positive_int,
        default=DEFAULT_ITERATIONS,
        help="timed samples per operation (default: %(default)s)",
    )
    parser.add_argument(
        "--warmup",
        type=non_negative_int,
        default=DEFAULT_WARMUP,
        help="warm-up rounds for timed primitives (default: %(default)s)",
    )
    parser.add_argument(
        "--keygen-samples",
        type=positive_int,
        default=DEFAULT_KEYGEN_SAMPLES,
        help="RSA key-generation samples per key size (default: %(default)s)",
    )
    parser.add_argument(
        "--hash-ops-per-sample",
        type=positive_int,
        default=DEFAULT_HASH_OPS_PER_SAMPLE,
        help="SHA-256 calls batched into each timed sample (default: %(default)s)",
    )
    parser.add_argument(
        "--sizes",
        type=int,
        choices=KEY_SIZES,
        nargs="+",
        default=list(KEY_SIZES),
        metavar="BITS",
        help="RSA key sizes to measure (default: 2048 3072)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    run_benchmark(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
