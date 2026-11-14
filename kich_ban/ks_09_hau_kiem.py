import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from kich_ban.common import report_result

SO = 9
TEN = "Hậu kiểm độc lập bản tin KS-01 đã lưu"
NHOM = "Luồng hợp lệ và hậu kiểm"
KY_VONG = "SIGNATURE_VALID"
TANG = "T0/T1/T1b/T4/T5"


def chay(env, *, verbose: bool = False):
    packet = env.data.get("ks01_packet")
    if packet is None:
        packet = env.merchant.create_packet(message_id="TX-2026-0009")
        env.data["ks01_packet"] = packet
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        mode="postcheck",
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
