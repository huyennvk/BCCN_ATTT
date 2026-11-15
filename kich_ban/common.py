from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from typing import Any

from he_thong import Environment

_LAYER_ORDER = ("T0", "T1", "T1b", "T2", "T3", "T4", "T5")
_LAYER_LABELS = {
    "T0": "cấu trúc",
    "T1": "chứng thư",
    "T1b": "danh tính",
    "T2": "thời gian",
    "T3": "chống phát lại",
    "T4": "toàn vẹn",
    "T5": "chữ ký",
}
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


def _log_layer_event(event: str) -> None:
    parts = event.split(" ", 1)
    layer = parts[0]
    status = parts[1] if len(parts) == 2 else ""
    label = _LAYER_LABELS.get(layer)
    if label is None:
        print("  [Issuer] G5 %s" % event)
    else:
        print("  [Issuer] G5 %s %s: %s" % (layer, label, status))


def print_flow_log(
    label: str,
    actual: str,
    expected: str,
    trace: list[str],
    *,
    group: str | None = None,
    g2_actor: str = "Merchant",
    g2_action: str = "tạo bản tin",
    g3_actor: str = "Merchant",
    g3_action: str = "chuẩn hóa và ký",
    g4_action: str | None = "chuyển tiếp",
    event_note: str | None = None,
) -> bool:
    """Print the G-stage flow without packet data; event notes contain action labels only."""
    ok = actual == expected
    path = format_layer_path(actual, trace)
    last_event = path.split(" → ")[-1]
    final_layer = last_event.split(" ", 1)[0]
    if actual == "SIGNATURE_VALID":
        stop_text = "hoàn tất"
    elif final_layer in _LAYER_LABELS:
        stop_text = "dừng tại %s" % final_layer
    else:
        stop_text = "dừng trong G5"

    print("Trích log %s — %s" % (label, stop_text))
    if group:
        print("%s · NHÓM %s" % (label, group.upper()))
    print("[%s] G2 %s: PASS" % (g2_actor, g2_action))
    print("[%s] G3 %s: PASS" % (g3_actor, g3_action))
    if g4_action is None:
        print("[Proxy] G4 bỏ qua trong hậu kiểm bản tin đã lưu")
    else:
        print("[Proxy] G4 %s: PASS" % g4_action)
    if event_note:
        print("[Sự kiện] %s" % event_note)

    print("[Issuer] G5 xác minh:")
    for event in path.split(" → "):
        _log_layer_event(event)

    print("[Phán quyết] G6: %s" % actual)
    print("[Đối chiếu] G8 kỳ vọng/thực tế: %s" % ("PASS" if ok else "FAIL"))
    return ok


def report_result(
    env: Environment,
    number: int,
    _title: str,
    packet: Any,
    expected: str,
    *,
    mode: str = "live",
    group: str | None = None,
    g2_actor: str = "Merchant",
    g2_action: str = "tạo bản tin",
    g3_actor: str = "Merchant",
    g3_action: str = "chuẩn hóa và ký",
    g4_action: str | None = "chuyển tiếp",
    event_note: str | None = None,
    verbose: bool = False,
) -> bool:
    trace: list[str] = []
    actual = env.issuer.verify_packet(packet, mode=mode, trace=trace)
    return print_flow_log(
        "KS-%02d" % number,
        actual,
        expected,
        trace,
        group=group,
        g2_actor=g2_actor,
        g2_action=g2_action,
        g3_actor=g3_actor,
        g3_action=g3_action,
        g4_action=g4_action,
        event_note=event_note,
    )


if __name__ == "__main__":
    from run_scenarios import main
    raise SystemExit(main())
