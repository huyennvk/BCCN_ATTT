from cryptography.hazmat.primitives.asymmetric import rsa

from kich_ban.common import report_result

SO = 10
TEN = "Chứng thư CA cấp cho khóa RSA-1024"
NHOM = "Danh tính"
KY_VONG = "KEY_TOO_WEAK"
TANG = "T1"


def chay(env):
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert_id, _ = env.ca.issue("MERCH-01", weak_key.public_key())
    packet = env.merchant.create_packet(message_id="TX-2026-0010")
    packet["CertificateID"] = cert_id
    return report_result(env, SO, TEN, packet, KY_VONG)
