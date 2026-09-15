"""Signature verification: authentic, tampered, malformed, and missing inputs."""

import hashlib
import hmac

import pytest

from webhook_guard.signature import (
    SignatureError,
    compute_signature,
    verify_signature,
)

SECRET = "whsec_test_secret"
TIMESTAMP = "1757952000"
BODY = b'{"id":"evt_123","type":"payment.succeeded"}'


def sign(secret: str = SECRET, timestamp: str = TIMESTAMP, body: bytes = BODY) -> str:
    """Independently produce a digest, without reusing the module under test."""
    payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def test_accepts_an_authentic_signature():
    verify_signature(SECRET, TIMESTAMP, BODY, sign())


def test_matches_an_independently_computed_digest():
    assert compute_signature(SECRET, TIMESTAMP, BODY) == sign()


def test_rejects_a_tampered_body():
    tampered = BODY.replace(b"evt_123", b"evt_999")
    with pytest.raises(SignatureError):
        verify_signature(SECRET, TIMESTAMP, tampered, sign())


def test_rejects_a_substituted_timestamp():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, "1757955600", BODY, sign())


def test_rejects_a_signature_made_with_the_wrong_secret():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, TIMESTAMP, BODY, sign(secret="whsec_wrong"))


def test_rejects_a_malformed_signature():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, TIMESTAMP, BODY, "not-a-hex-digest")


@pytest.mark.parametrize(
    ("secret", "timestamp", "provided"),
    [
        ("", TIMESTAMP, sign()),
        (SECRET, "", sign()),
        (SECRET, TIMESTAMP, ""),
    ],
    ids=["missing-secret", "missing-timestamp", "missing-signature"],
)
def test_rejects_missing_inputs(secret, timestamp, provided):
    with pytest.raises(SignatureError):
        verify_signature(secret, timestamp, BODY, provided)


def test_body_is_compared_as_raw_bytes():
    """Re-serializing JSON changes the bytes, so the signature must fail."""
    reserialized = b'{"type": "payment.succeeded", "id": "evt_123"}'
    assert reserialized != BODY
    with pytest.raises(SignatureError):
        verify_signature(SECRET, TIMESTAMP, reserialized, sign())
