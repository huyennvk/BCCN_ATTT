from kich_ban.common import report_result

SO = 11
TEN = "Bỏ trường MessageHash khỏi envelope"
NHOM = "Cấu trúc"
KY_VONG = "MALFORMED"
TANG = "T0"


def chay(env):
    packet = env.merchant.create_packet(message_id="TX-2026-0011")
    del packet["MessageHash"]
    return report_result(env, SO, TEN, packet, KY_VONG)
