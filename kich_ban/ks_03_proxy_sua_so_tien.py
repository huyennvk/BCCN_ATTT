from kich_ban.common import report_result
from he_thong import Proxy

SO = 3
TEN = "Proxy sửa Amount 150000 thành 1500000"
NHOM = "Toàn vẹn"
KY_VONG = "INTEGRITY_VIOLATION"
TANG = "T4"


def chay(env):
    packet = env.merchant.create_packet(message_id="TX-2026-0003", amount=150_000)
    tampered = Proxy.modify(packet, "Amount", 1_500_000)
    return report_result(
        env,
        SO,
        TEN,
        tampered,
        KY_VONG,
        original_packet=packet,
        scenario_note="Proxy đổi Amount sau khi ký nhưng không tính lại MessageHash hoặc Signature.",
    )
