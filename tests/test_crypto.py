import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from rsa_crypto import (
    CanonicalizationError,
    canonical_json_bytes,
    generate_nonce,
    sign,
    strict_json_loads,
    verify,
)


def test_rsa_pss_round_trip_and_tamper():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"fintech payment-message test"
    signature = sign(private_key, message)
    assert verify(private_key.public_key(), message, signature)
    assert not verify(private_key.public_key(), message + b"!", signature)


def test_nonce_is_128_bit_hex():
    nonce = generate_nonce()
    assert len(nonce) == 32
    assert int(nonce, 16) >= 0


def test_canonical_json_is_stable_and_normalizes_unicode():
    left = {"b": "e\u0301", "a": 1}
    right = {"a": 1, "b": "é"}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)


def test_canonical_json_rejects_float_and_nfc_key_collision():
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"amount": 1.25})
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"é": 1, "e\u0301": 2})


def test_strict_json_rejects_duplicate_keys_even_after_nfc():
    with pytest.raises(CanonicalizationError):
        strict_json_loads('{"Amount":1,"Amount":2}')
    with pytest.raises(CanonicalizationError):
        strict_json_loads('{"é":1,"e\\u0301":2}')


def test_strict_json_rejects_float_and_oversized_input():
    with pytest.raises(CanonicalizationError):
        strict_json_loads('{"Amount":1.0}')
    with pytest.raises(CanonicalizationError):
        strict_json_loads(" " * 16_385)
