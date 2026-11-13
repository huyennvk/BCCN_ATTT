from __future__ import annotations

import json
from typing import Any

from he_thong import Environment
from rsa_crypto import CanonicalizationError, canonical_json_bytes, sha256_hex

_MISSING = object()


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


def _print_compact_report(number: int, title: str, actual: str, expected: str, ok: bool) -> None:
    status = "ĐẠT" if ok else "KHÔNG ĐẠT (kỳ vọng: %s)" % expected
    print("KS-%02d · %s | %s | %s" % (number, title, actual, status))


def report_result(
    env: Environment,
    number: int,
    title: str,
    packet: Any,
    expected: str,
    *,
    mode: str = "live",
    original_packet: Any | None = None,
    scenario_note: str | None = None,
    verbose: bool = False,
) -> bool:
    trace: list[str] = []
    actual = env.issuer.verify_packet(packet, mode=mode, trace=trace)
    ok = actual == expected
    if not verbose:
        _print_compact_report(number, title, actual, expected, ok)
        return ok

    print("\nKS-%02d · %s" % (number, title))
    if scenario_note:
        print("  Bối cảnh: %s" % scenario_note)

    if original_packet is not None:
        print_packet_material("Gói Merchant/Signer tạo và ký ban đầu:", original_packet)
        if original_packet == packet:
            print("  Gói đưa vào Issuer: giữ nguyên như gói đã ký.")
        else:
            print_packet_material("Gói sau tác động, Issuer nhận:", packet)
            _print_packet_diff(original_packet, packet)
    else:
        print_packet_material("Gói đưa vào Issuer:", packet)

    print("  Các bước Issuer xử lý:")
    for step in trace:
        print("    %s" % step)
    print(
        "  Issuer quyết định: %s | Kịch bản: %s (kỳ vọng: %s)"
        % (actual, "ĐẠT" if ok else "KHÔNG ĐẠT", expected)
    )
    return ok
