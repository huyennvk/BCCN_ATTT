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
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        verbose=verbose,
        scenario_note="ATTACK-01 ký payload tự khai MerchantID=MERCH-01; CertificateID thuộc chứng thư của ATTACK-01.",
    )
