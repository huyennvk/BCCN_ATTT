from datetime import timedelta

from he_thong import Proxy
from kich_ban.common import report_result

SO = 1
TEN = "Ký và gửi bản tin chuẩn"
NHOM = "Bình thường"
KY_VONG = "SIGNATURE_VALID"
TANG = "T0-T5"


def chay(env, *, verbose: bool = False):
    now = env.clock.now()
    packet = env.merchant.create_packet(
        message_id="TX-2026-0001",
        timestamp=now - timedelta(seconds=10),
    )
    env.data["ks01_packet"] = packet
    forwarded = Proxy.forward(packet)
    return report_result(
        env,
        SO,
        TEN,
        forwarded,
        KY_VONG,
        verbose=verbose,
        original_packet=packet,
        scenario_note="Merchant tạo payload 7 trường, ký RSA-PSS; Proxy chuyển tiếp nguyên vẹn gói đến Issuer.",
    )
