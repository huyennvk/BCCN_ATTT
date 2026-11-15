import copy
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from he_thong import Proxy
from kich_ban.common import report_result
from rsa_crypto import canonical_json_bytes, sign

SO = 7
TEN = "Ký bằng khóa lạ nhưng khai báo chứng thư Merchant"
NHOM = "Chữ ký và chính sách khóa"
KY_VONG = "SIGNATURE_INVALID"
TANG = "T5"


def chay(env, *, verbose: bool = False):
    original = env.merchant.create_packet(message_id="TX-2026-0007")
    packet = copy.deepcopy(original)
    packet["Signature"] = sign(
        env.attacker.private_key,
        canonical_json_bytes(packet["payload"]),
    ).hex()
    # Giữ CertificateID của Merchant nhưng thay chữ ký bằng chữ ký ATTACK-01.
    packet = Proxy.forward(packet)
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g3_actor="ATTACK-01",
        g3_action="ký theo kịch bản",
        event_note="ATTACK-01 thay chữ ký",
    )


if __name__ == "__main__":
    from run_scenarios import BASE_TIME, FrozenClock, create_environment
    env = create_environment(clock=FrozenClock(BASE_TIME))
    chay(env, verbose=True)
