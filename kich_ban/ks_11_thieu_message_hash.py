import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from kich_ban.common import report_result

SO = 11
TEN = "Bỏ trường MessageHash khỏi envelope"
NHOM = "Toàn vẹn và cấu trúc"
KY_VONG = "MALFORMED"
TANG = "T0"


def chay(env, *, verbose: bool = False):
    original = env.merchant.create_packet(message_id="TX-2026-0011")
    packet = dict(original)
    del packet["MessageHash"]
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
