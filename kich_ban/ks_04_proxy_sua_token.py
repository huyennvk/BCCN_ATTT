from kich_ban.common import report_result
from he_thong import Proxy

SO = 4
TEN = "Proxy sửa một ký tự trong CardToken"
NHOM = "Toàn vẹn"
KY_VONG = "INTEGRITY_VIOLATION"
TANG = "T4"


def chay(env, *, verbose: bool = False):
    packet = env.merchant.create_packet(message_id="TX-2026-0004", card_token="tok_9f2e77ab")
    tampered = Proxy.modify(packet, "CardToken", "tok_9f2e77ac")
    return report_result(
        env,
        SO,
        TEN,
        tampered,
        KY_VONG,
        verbose=verbose,
        original_packet=packet,
        scenario_note="Proxy đổi một ký tự trong CardToken sau khi ký; MessageHash và Signature vẫn là giá trị cũ.",
    )
