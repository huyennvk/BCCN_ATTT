from datetime import timedelta

from kich_ban.common import report_result

SO = 6
TEN = "Merchant dùng lại nonce KS-01 với MessageID mới"
NHOM = "Thời gian và chống phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env, *, verbose: bool = False):
    base = env.data.get("ks01_packet")
    if base is None:
        from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01
        chay_ks01(env, verbose=verbose)
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
        verbose=verbose,
        original_packet=packet,
        scenario_note=(
            "Merchant giữ khóa hợp lệ nhưng sinh lỗi khi tái sử dụng Nonce của KS-01; "
            "MessageID mới, Timestamp còn hạn. Proxy chỉ chuyển tiếp gói và không thể tạo chữ ký mới."
        ),
    )
