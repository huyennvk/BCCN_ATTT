import contextlib
import io
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from kich_ban.common import report_result

SO = 2
TEN = "Hậu kiểm độc lập bản tin KS-01 đã lưu"
NHOM = "Luồng hợp lệ và hậu kiểm"
KY_VONG = "SIGNATURE_VALID"
TANG = "T0/T1/T1b/T4/T5"


def chay(env, *, verbose: bool = False):
    packet = env.data.get("ks01_packet")
    if packet is None:
        from kich_ban.ks_01_ban_tin_chuan import chay as chay_ks01

        # Chuẩn bị bản tin KS-01 đã được chấp nhận, nhưng chỉ in log hậu kiểm KS-02.
        with contextlib.redirect_stdout(io.StringIO()):
            chay_ks01(env)
        packet = env.data["ks01_packet"]
    g2_action = "dùng bản tin lưu sẵn"
    g3_action = "dùng chữ ký lưu sẵn"
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g2_action=g2_action,
        g3_action=g3_action,
        g4_action=None,
        mode="postcheck",
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
