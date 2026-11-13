from kich_ban.common import report_result
from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01

SO = 2
TEN = "Gửi lại nguyên văn bản tin KS-01"
NHOM = "Phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env, *, verbose: bool = False):
    packet = env.data.get("ks01_packet")
    if packet is None:
        chay_ks01(env, verbose=verbose)
        packet = env.data["ks01_packet"]
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        verbose=verbose,
        original_packet=packet,
        scenario_note="Phát lại đúng gói KS-01: MessageID và Nonce vẫn giữ nguyên, không sửa payload hay chữ ký.",
    )
