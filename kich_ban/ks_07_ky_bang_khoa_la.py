import copy

from kich_ban.common import report_result
from rsa_crypto import canonical_json_bytes, sign

SO = 7
TEN = "Ký bằng khóa lạ nhưng khai báo chứng thư Merchant"
NHOM = "Danh tính"
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
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        verbose=verbose,
        original_packet=original,
        scenario_note="Payload và MessageHash không đổi; chỉ Signature được tạo lại bằng khóa ATTACK-01, còn CertificateID của Merchant được giữ nguyên.",
    )
