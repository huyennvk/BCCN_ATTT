from __future__ import annotations

from typing import Any

from he_thong import Environment


def report_result(
    env: Environment,
    number: int,
    title: str,
    packet: Any,
    expected: str,
    *,
    mode: str = "live",
) -> bool:
    trace: list[str] = []
    actual = env.issuer.verify_packet(packet, mode=mode, trace=trace)
    ok = actual == expected
    print("\nKS-%02d · %s" % (number, title))
    for step in trace:
        print("  %s" % step)
    print("  expected=%s actual=%s => %s" % (expected, actual, "PASS" if ok else "FAIL"))
    return ok
