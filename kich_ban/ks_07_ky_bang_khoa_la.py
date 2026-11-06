from kich_ban.common import report_result
from rsa_crypto import canonical_json_bytes, sign

SO = 7
TEN = "Ký bằng khóa lạ nhưng khai báo chứng thư Merchant"
NHOM = "Danh tính"
KY_VONG = "SIGNATURE_INVALID"
TANG = "T5"


def chay(env):
    packet = env.merchant.create_packet(message_id="TX-2026-0007")
    packet["Signature"] = sign(
        env.attacker.private_key,
        canonical_json_bytes(packet["payload"]),
    ).hex()
    # Giữ CertificateID của Merchant nhưng ký bằng khóa ATTACK-01.
    return report_result(env, SO, TEN, packet, KY_VONG)
