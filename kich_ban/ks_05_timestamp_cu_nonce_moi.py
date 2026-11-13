from datetime import timedelta

from kich_ban.common import report_result

SO = 5
TEN = "Timestamp lùi một giờ, nonce mới"
NHOM = "Phát lại"
KY_VONG = "TIMESTAMP_TOO_OLD"
TANG = "T2"


def chay(env, *, verbose: bool = False):
    packet = env.merchant.create_packet(
        message_id="TX-2026-0005",
        timestamp=env.clock.now() - timedelta(hours=1),
    )
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        verbose=verbose,
        original_packet=packet,
        scenario_note="Timestamp cũ hơn đồng hồ Issuer một giờ; Nonce mới, payload và chữ ký được tạo cùng nhau.",
    )
