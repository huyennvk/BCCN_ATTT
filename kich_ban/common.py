from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from typing import Any

from he_thong import Environment

_LAYER_ORDER = ("T0", "T1", "T1b", "T2", "T3", "T4", "T5")
_PASS_MARKERS = {
    "T0": "T0 result: PASS",
    "T1": "T1 certificate chain, validity, revocation and key policy: PASS",
    "T1b": "T1b result: PASS",
    "T2": "T2 result: PASS",
    "T3": "T3 result: PASS",
    "T4": "T4 result: PASS",
    "T5": "T5 result: PASS",
}
_ERROR_LAYER = {
    "CERT_NOT_FOUND": "T1",
    "CHAIN_INVALID": "T1",
    "CERT_NOT_YET_VALID": "T1",
    "CERT_EXPIRED": "T1",
    "CERT_REVOKED": "T1",
    "KEY_TOO_WEAK": "T1",
    "WEAK_EXPONENT": "T1",
    "CERT_POLICY_INVALID": "T1",
    "SIGNER_NOT_AUTHORIZED": "T1b",
    "TIMESTAMP_TOO_OLD": "T2",
    "TIMESTAMP_IN_FUTURE": "T2",
    "REPLAY_DETECTED": "T3",
    "DUPLICATE_MESSAGE": "T3",
    "INTEGRITY_VIOLATION": "T4",
    "SIGNATURE_INVALID": "T5",
}


def _failure_layer(actual: str, trace: list[str]) -> str:
    if actual == "MALFORMED":
        for line in reversed(trace):
            if "-> MALFORMED" in line:
                layer = line.split(" ", 1)[0]
                if layer in _LAYER_ORDER:
                    return layer
        return "T0"
    if actual == "SERVICE_UNAVAILABLE":
        if any(line.startswith("T1 CRL input: unavailable") for line in trace):
            return "T1"
        return "T3"
    return _ERROR_LAYER.get(actual, "T5")


def format_layer_path(actual: str, trace: list[str]) -> str:
    """Return only layer PASS markers and the decision error, never packet data."""
    passed = {
        layer
        for layer, marker in _PASS_MARKERS.items()
        if any(line.startswith(marker) for line in trace)
    }
    late_commit_error = any(
        line.startswith("T3 atomic reservation result: conflict=")
        or line.startswith("T3 atomic reservation: state store unavailable")
        for line in trace
    )

    if actual == "SIGNATURE_VALID":
        events = ["%s PASS" % layer for layer in _LAYER_ORDER if layer in passed]
    elif late_commit_error:
        events = ["%s PASS" % layer for layer in _LAYER_ORDER if layer in passed]
        events.append("T3 COMMIT %s" % actual)
    else:
        failed_layer = _failure_layer(actual, trace)
        events = []
        for layer in _LAYER_ORDER:
            if layer == failed_layer:
                events.append("%s %s" % (layer, actual))
                break
            if layer in passed:
                events.append("%s PASS" % layer)
        if not events:
            events.append("ERROR %s" % actual)

    return " → ".join(events)


def report_result(
    env: Environment,
    number: int,
    _title: str,
    packet: Any,
    expected: str,
    *,
    mode: str = "live",
) -> bool:
    trace: list[str] = []
    actual = env.issuer.verify_packet(packet, mode=mode, trace=trace)
    ok = actual == expected
    path = format_layer_path(actual, trace)
    if ok:
        print("KS-%02d PASS | %s" % (number, path))
    else:
        print("KS-%02d FAIL | %s" % (number, path))
    return ok


if __name__ == "__main__":
    from run_scenarios import main
    raise SystemExit(main())
