from kich_ban.common import report_result

SO = 11
TEN = "Bỏ trường MessageHash khỏi envelope"
NHOM = "Cấu trúc"
KY_VONG = "MALFORMED"
TANG = "T0"


def chay(env):
    original = env.merchant.create_packet(message_id="TX-2026-0011")
    packet = dict(original)
    del packet["MessageHash"]
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        original_packet=original,
        scenario_note="Proxy xóa trường MessageHash khỏi envelope; các trường khác được giữ nguyên.",
    )
