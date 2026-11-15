from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from typing import Any

from he_thong import Environment
from rsa_crypto import CanonicalizationError, canonical_json_bytes, sha256_hex

_MISSING = object()

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


def _json_text(value: Any, *, pretty: bool = False) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )
    except (TypeError, ValueError):
        return repr(value)


def _signature_summary(value: Any) -> str:
    if not isinstance(value, str):
        return "<không phải chuỗi hex>"
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return "%s (hex không hợp lệ)" % _json_text(value)
    if len(value) <= 64:
        preview = value
    else:
        preview = "%s…%s" % (value[:32], value[-16:])
    return "%s (%d ký tự hex, %d byte)" % (preview, len(value), len(raw))


def _display_value(field: str, value: Any) -> str:
    if value is _MISSING:
        return "<không có>"
    if field == "Signature":
        return _signature_summary(value)
    text = _json_text(value)
    if len(text) > 120:
        return text[:96] + "…" + text[-16:]
    return text


def print_packet_material(label: str, packet: Any) -> None:
    print("  %s" % label)
    if not isinstance(packet, dict):
        print("    Envelope nhận được: %s" % _display_value("packet", packet))
        return

    envelope_fields = ", ".join(sorted(str(key) for key in packet))
    print("    Trường envelope: {%s}" % envelope_fields)
    payload = packet.get("payload", _MISSING)
    if not isinstance(payload, dict):
        print("    Payload: %s" % _display_value("payload", payload))
        canonical = None
    else:
        print("    Payload JSON (dữ liệu có thể đọc):")
        for line in _json_text(payload, pretty=True).splitlines():
            print("      " + line)
        print("    Ghi chú: payload không bị mã hóa; JSON chuẩn hóa được dùng để băm và tạo/xác minh chữ ký, không che nội dung.")
        try:
            canonical = canonical_json_bytes(payload)
            canonical_text = canonical.decode("utf-8")
            print("    Canonical JSON UTF-8 (%d byte):" % len(canonical))
            print("      " + canonical_text)
            computed_hash = sha256_hex(canonical)
            declared_hash = packet.get("MessageHash", _MISSING)
            print("    SHA-256(canonical JSON) = %s" % computed_hash)
            print("    MessageHash trong envelope = %s" % _display_value("MessageHash", declared_hash))
            print("    Hash khớp = %s" % ("CÓ" if declared_hash == computed_hash else "KHÔNG"))
        except (CanonicalizationError, UnicodeError) as exc:
            canonical = None
            print("    Canonical JSON: không tạo được (%s)" % exc)

    signature = packet.get("Signature", _MISSING)
    if signature is _MISSING:
        print("    Signature: <không có>")
    else:
        print("    Signature RSA-PSS/SHA-256 (hex, xem trước): %s" % _signature_summary(signature))
    print("    CertificateID = %s" % _display_value("CertificateID", packet.get("CertificateID", _MISSING)))


def _print_packet_diff(before: Any, after: Any) -> None:
    print("  Thay đổi giữa gói đã ký và gói Issuer nhận:")
    if not isinstance(before, dict) or not isinstance(after, dict):
        print("    Không thể so sánh: một trong hai envelope không phải object.")
        return

    before_payload = before.get("payload")
    after_payload = after.get("payload")
    changed = False
    if isinstance(before_payload, dict) and isinstance(after_payload, dict):
        for field in sorted(set(before_payload) | set(after_payload)):
            old = before_payload.get(field, _MISSING)
            new = after_payload.get(field, _MISSING)
            if old != new:
                changed = True
                print(
                    "    payload.%s: %s → %s"
                    % (field, _display_value(field, old), _display_value(field, new))
                )
    elif before_payload != after_payload:
        changed = True
        print(
            "    payload: %s → %s"
            % (_display_value("payload", before_payload), _display_value("payload", after_payload))
        )

    for field in ("MessageHash", "Signature", "CertificateID"):
        old = before.get(field, _MISSING)
        new = after.get(field, _MISSING)
        if old != new:
            changed = True
            print("    %s: %s → %s" % (field, _display_value(field, old), _display_value(field, new)))
        elif old is not _MISSING:
            print("    %s: giữ nguyên" % field)

    if not changed:
        print("    Không có trường dữ liệu nào bị thay đổi.")


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
    original_packet: Any | None = None,
    packet: Any | None = None,
    detail: bool = False,
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

    if detail:
        if original_packet is not None:
            print_packet_material("Gói Merchant/Signer tạo và ký ban đầu:", original_packet)
            if packet is not None and original_packet != packet:
                print_packet_material("Gói sau tác động, Issuer nhận:", packet)
                _print_packet_diff(original_packet, packet)
            elif original_packet == packet:
                print("  Gói đưa vào Issuer: giữ nguyên như gói đã ký.")
        elif packet is not None:
            print_packet_material("Gói đưa vào Issuer:", packet)

    print("[Issuer] G5 xác minh:")
    for event in path.split(" → "):
        _log_layer_event(event)

    if detail and trace:
        print("  [Chi tiết Issuer kiểm tra]:")
        for step in trace:
            print("    %s" % step)

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
    original_packet: Any | None = None,
    detail: bool = False,
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
        original_packet=original_packet,
        packet=packet,
        detail=detail,
    )


if __name__ == "__main__":
    from run_scenarios import main
    raise SystemExit(main())
