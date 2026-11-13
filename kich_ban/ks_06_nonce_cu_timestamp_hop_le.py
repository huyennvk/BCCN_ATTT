from datetime import timedelta

from kich_ban.common import report_result

SO = 6
TEN = "Timestamp còn hạn, dùng lại nonce KS-01 với MessageID mới"
NHOM = "Phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env):
    base = env.data.get("ks01_packet")
    if base is None:
        from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01
        chay_ks01(env)
        base = env.data["ks01_packet"]
    packet = env.merchant.create_packet(
        message_id="TX-2026-0006",
        timestamp=env.clock.now() - timedelta(seconds=10),
        nonce=base["payload"]["Nonce"],
    )
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        original_packet=packet,
        scenario_note="MessageID mới nhưng Nonce được lấy lại từ KS-01; Timestamp vẫn nằm trong cửa sổ cho phép.",
    )
