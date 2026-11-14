import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from datetime import timedelta

from he_thong import Proxy
from kich_ban.common import report_result

SO = 1
TEN = "Ký và gửi bản tin chuẩn"
NHOM = "Luồng hợp lệ và hậu kiểm"
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
        group=NHOM,
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
