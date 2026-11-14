from he_thong import Proxy
from kich_ban.common import report_result

SO = 11
TEN = "Bỏ trường MessageHash khỏi envelope"
NHOM = "Toàn vẹn và cấu trúc"
KY_VONG = "MALFORMED"
TANG = "T0"


def chay(env, *, verbose: bool = False):
    original = env.merchant.create_packet(message_id="TX-2026-0011")
    packet = Proxy.remove_envelope_field(original, "MessageHash")
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g4_action="tác động theo kịch bản",
    )
