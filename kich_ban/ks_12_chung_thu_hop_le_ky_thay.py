import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from he_thong import Proxy
from kich_ban.common import format_simulation_time, report_result

SO = 12
TEN = "Chứng thư hợp lệ của ATTACK-01 ký thay MERCH-01"
NHOM = "Chứng thư và quyền ký"
KY_VONG = "SIGNER_NOT_AUTHORIZED"
TANG = "T1b"


def chay(env, *, verbose: bool = False):
    payload = env.merchant.make_payload(
        message_id="TX-2026-0012",
        amount=99_000_000,
        merchant_id="MERCH-01",
    )
    packet = env.attacker.sign_payload(payload)
    attack_time = format_simulation_time(env)
    packet = Proxy.forward(packet)
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g3_actor="ATTACK-01",
        event_note="ATTACK-01 ký thay MERCH-01 lúc %s" % attack_time,
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
