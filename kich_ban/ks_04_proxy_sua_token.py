import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from kich_ban.common import report_result
from he_thong import Proxy

SO = 4
TEN = "Proxy sửa một ký tự trong CardToken"
NHOM = "Toàn vẹn và cấu trúc"
KY_VONG = "INTEGRITY_VIOLATION"
TANG = "T4"


def chay(env, *, verbose: bool = False):
    packet = env.merchant.create_packet(message_id="TX-2026-0004", card_token="tok_9f2e77ab")
    tampered = Proxy.modify(packet, "CardToken", "tok_9f2e77ac")
    return report_result(
        env,
        SO,
        TEN,
        tampered,
        KY_VONG,
        group=NHOM,
        g4_action="tác động theo kịch bản",
        event_note="Tấn công Proxy sửa gói",
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
