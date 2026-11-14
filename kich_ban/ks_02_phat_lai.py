import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from kich_ban.common import report_result
from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01

SO = 2
TEN = "Gửi lại nguyên văn bản tin KS-01"
NHOM = "Thời gian và chống phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env, *, verbose: bool = False):
    packet = env.data.get("ks01_packet")
    if packet is None:
        chay_ks01(env)
        packet = env.data["ks01_packet"]
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
