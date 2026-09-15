"""HMAC signature verification for inbound webhook deliveries.

The provider signs ``{timestamp}.{raw_body}`` with a shared secret and sends
the digest in a header. We recompute it from the bytes we received and compare
in constant time.

This module is deliberately framework-agnostic: it takes bytes and strings, not
request objects, so it can be tested without a server and reused behind any
transport.
"""

from __future__ import annotations

import hashlib
import hmac


class SignatureError(Exception):
    """Raised when a delivery's signature cannot be verified."""


def compute_signature(secret: str, timestamp: str, body: bytes) -> str:
    """Return the hex digest the provider should have sent for this delivery.

    The timestamp is bound into the signed payload so it cannot be altered
    independently of the body. Replay-window enforcement depends on that.
    """
    signed_payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(secret: str, timestamp: str, body: bytes, provided: str) -> None:
    """Verify a delivery's signature, raising ``SignatureError`` if it fails.

    Comparison uses :func:`hmac.compare_digest`, which examines the full digest
    regardless of where the first mismatch occurs. A short-circuiting ``==``
    would leak the position of that mismatch through response timing, letting an
    attacker recover a valid signature one byte at a time.
    """
    if not secret:
        raise SignatureError("signing secret is not configured")
    if not timestamp:
        raise SignatureError("timestamp is missing")
    if not provided:
        raise SignatureError("signature is missing")

    expected = compute_signature(secret, timestamp, body)

    if not hmac.compare_digest(expected, provided):
        raise SignatureError("signature does not match")
