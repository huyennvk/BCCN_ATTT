import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from datetime import timedelta

from he_thong import Proxy
from kich_ban.common import format_simulation_time, report_result

SO = 6
TEN = "Merchant dùng lại nonce KS-01 với MessageID mới"
NHOM = "Thời gian và chống phát lại"
KY_VONG = "REPLAY_DETECTED"
TANG = "T3"


def chay(env, *, verbose: bool = False):
    base = env.data.get("ks01_packet")
    if base is None:
        from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01
        chay_ks01(env)
        base = env.data["ks01_packet"]
    creation_time = format_simulation_time(env)
    packet = env.merchant.create_packet(
        message_id="TX-2026-0006",
        timestamp=env.clock.now() - timedelta(seconds=10),
        nonce=base["payload"]["Nonce"],
    )
    packet = Proxy.forward(packet)
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        event_note=(
            "Merchant tạo bản tin dùng lại nonce lúc %s (không phải Proxy)"
            % creation_time
        ),
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
