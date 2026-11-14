from he_thong import Proxy
from kich_ban.common import report_result

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
    packet = Proxy.forward(packet)
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        group=NHOM,
        g3_actor="ATTACK-01",
    )
