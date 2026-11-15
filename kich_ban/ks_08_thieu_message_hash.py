import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from he_thong import Proxy
from kich_ban.common import report_result

SO = 8
TEN = "Bỏ trường MessageHash khỏi envelope"
NHOM = "Toàn vẹn và cấu trúc"
KY_VONG = "MALFORMED"
TANG = "T0"


def chay(env, *, verbose: bool = False, detail: bool = False):
    original = env.merchant.create_packet(message_id="TX-2026-0011")
    packet = Proxy.remove_envelope_field(original, "MessageHash")
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g4_action="tác động theo kịch bản",
        event_note="Tấn công Proxy sửa envelope",
        verbose=verbose,
        detail=detail,
        original_packet=original,
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True, detail=True)
