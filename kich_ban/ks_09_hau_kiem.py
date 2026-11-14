from kich_ban.common import report_result

SO = 9
TEN = "Hậu kiểm độc lập bản tin KS-01 đã lưu"
NHOM = "Luồng hợp lệ và hậu kiểm"
KY_VONG = "SIGNATURE_VALID"
TANG = "T0/T1/T1b/T4/T5"


def chay(env, *, verbose: bool = False):
    packet = env.data.get("ks01_packet")
    if packet is None:
        packet = env.merchant.create_packet(message_id="TX-2026-0009")
        env.data["ks01_packet"] = packet
    return report_result(
        env,
        SO,
        TEN,
        packet,
        KY_VONG,
        verbose=verbose,
        mode="postcheck",
        original_packet=packet,
        scenario_note="Issuer hậu kiểm bản tin đã lưu; bỏ qua kiểm tra Timestamp mới và tiêu thụ Nonce lần nữa.",
    )
