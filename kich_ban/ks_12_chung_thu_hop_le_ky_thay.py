from kich_ban.common import report_result

SO = 12
TEN = "Chứng thư hợp lệ của ATTACK-01 ký thay MERCH-01"
NHOM = "Danh tính"
KY_VONG = "SIGNER_NOT_AUTHORIZED"
TANG = "T1b"


def chay(env):
    payload = env.merchant.make_payload(
        message_id="TX-2026-0012",
        amount=99_000_000,
        merchant_id="MERCH-01",
    )
    packet = env.attacker.sign_payload(payload)
    return report_result(env, SO, TEN, packet, KY_VONG)
