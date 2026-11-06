from kich_ban.common import report_result
from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01

SO = 2
TEN = "Gửi lại nguyên văn bản tin KS-01"
NHOM = "Phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env):
    packet = env.data.get("ks01_packet")
    if packet is None:
        chay_ks01(env)
        packet = env.data["ks01_packet"]
    return report_result(env, SO, TEN, packet, KY_VONG)
