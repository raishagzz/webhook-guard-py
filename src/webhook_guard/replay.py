"""Replay-window enforcement for inbound webhook deliveries.

A captured delivery stays cryptographically valid forever: the signature proves
authenticity, not freshness. The provider binds a Unix timestamp into the signed
payload, so an attacker replaying a captured request cannot update it without
breaking the signature. Rejecting stale timestamps closes the gap.

The window is two-sided. Clocks drift between hosts, so a delivery stamped
slightly in the future is normal and a small forward tolerance avoids rejecting
legitimate traffic; a large one would let an attacker pre-sign for later use.
"""

from __future__ import annotations

import time

DEFAULT_TOLERANCE_SECONDS = 300


class ReplayError(Exception):
    """Raised when a delivery falls outside the accepted replay window."""


def parse_timestamp(timestamp: str) -> int:
    """Parse a Unix timestamp header, raising ``ReplayError`` if unusable."""
    if not timestamp:
        raise ReplayError("timestamp is missing")
    try:
        return int(timestamp)
    except ValueError as exc:
        raise ReplayError("timestamp is not an integer") from exc


def verify_timestamp(
    timestamp: str,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> None:
    """Verify a delivery is recent, raising ``ReplayError`` if it is not.

    ``now`` is injectable so tests can pin the clock rather than sleep.
    """
    sent_at = parse_timestamp(timestamp)
    current = int(time.time()) if now is None else now

    age = current - sent_at

    if age > tolerance_seconds:
        raise ReplayError(f"delivery is {age}s old, outside the {tolerance_seconds}s window")
    if -age > tolerance_seconds:
        raise ReplayError(f"delivery is timestamped {-age}s in the future")
