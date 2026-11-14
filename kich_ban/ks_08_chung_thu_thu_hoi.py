import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from datetime import timedelta

from kich_ban.common import report_result

SO = 8
TEN = "Ký bản tin bằng chứng thư Merchant đã bị thu hồi"
NHOM = "Chứng thư và quyền ký"
KY_VONG = "CERT_REVOKED"
TANG = "T1"


def chay(env, *, verbose: bool = False):
    now = env.clock.now()
    env.ca.revoke(env.merchant.certificate_id, when=now - timedelta(seconds=5))
    packet = env.merchant.create_packet(message_id="TX-2026-0008", timestamp=now)
    try:
        return report_result(
            env,
            SO,
            TEN,
            packet,
            KY_VONG,
        )
    finally:
        # Kịch bản độc lập: phục hồi trạng thái CA để không làm nhiễm KS-09.
        env.ca.unrevoke(env.merchant.certificate_id)


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
