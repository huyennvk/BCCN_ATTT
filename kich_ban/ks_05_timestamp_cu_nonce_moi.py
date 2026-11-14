from datetime import timedelta

from he_thong import Proxy
from kich_ban.common import report_result

SO = 5
TEN = "Proxy giữ lại rồi chuyển trễ gói hợp lệ"
NHOM = "Thời gian và chống phát lại"
KY_VONG = "TIMESTAMP_TOO_OLD"
TANG = "T2"


def chay(env, *, verbose: bool = False):
    original_packet = env.merchant.create_packet(message_id="TX-2026-0005")
    advance_clock = getattr(env.clock, "advance", None)
    if advance_clock is None:
        raise RuntimeError("KS-05 requires a controllable clock to model delayed delivery")

    saved_ca_crl = env.ca._crl
    saved_issuer_crl_cache = env.issuer._crl_cache
    advance_clock(timedelta(hours=1))
    try:
        packet = Proxy.forward(original_packet)
        return report_result(
            env,
            SO,
            TEN,
            packet,
            KY_VONG,
            verbose=verbose,
            original_packet=original_packet,
            scenario_note=(
                "Proxy giữ nguyên gói đã ký, chưa chuyển tới Issuer, rồi gửi sau 3600 giây; "
                "nonce chưa từng được ghi trong kho."
            ),
        )
    finally:
        # Roll back this isolated time jump because the full scenario suite
        # shares one deterministic environment and later cases need KS-01's nonce.
        advance_clock(-timedelta(hours=1))
        env.ca._crl = saved_ca_crl
        env.issuer._crl_cache = saved_issuer_crl_cache
