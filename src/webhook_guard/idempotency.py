"""Idempotent delivery handling for inbound webhooks.

Providers deliver at least once: a lost acknowledgment means the same event
arrives again, signed and fresh, passing every other guard. Recording processed
event IDs turns a repeat delivery into a no-op.

Claiming is a single atomic operation rather than a check followed by a write.
Two copies of one event arriving concurrently would otherwise both find the
store empty and both proceed.

An event is recorded only after its handler succeeds. A crash mid-processing
therefore lets the retry run the handler again — at-least-once, not
at-most-once. The alternative would mark an event done whose work never
happened, and nothing would ever retry it. Handlers are expected to tolerate
this; the store reduces duplicates, it cannot eliminate them.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol

DEFAULT_RETENTION_SECONDS = 86_400


class IdempotencyStore(Protocol):
    """Records which event IDs have been processed.

    The in-memory implementation below is process-local and does not survive a
    restart. A deployment running more than one worker needs a shared backend —
    Redis, or a table with a unique constraint on the event ID.
    """

    def claim(self, event_id: str) -> bool:
        """Claim an event, returning ``True`` if this caller won the claim."""
        ...

    def release(self, event_id: str) -> None:
        """Release a claim so a failed delivery can be retried."""
        ...


class InMemoryIdempotencyStore:
    """Process-local store with time-based expiry of old claims."""

    def __init__(
        self,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        now: object = None,
    ) -> None:
        self._claims: dict[str, float] = {}
        self._lock = threading.Lock()
        self._retention_seconds = retention_seconds
        self._now = now or time.time

    def claim(self, event_id: str) -> bool:
        if not event_id:
            raise ValueError("event id is required")

        current = self._now()
        with self._lock:
            self._expire(current)
            claimed_at = self._claims.setdefault(event_id, current)
            return claimed_at == current

    def release(self, event_id: str) -> None:
        with self._lock:
            self._claims.pop(event_id, None)

    def _expire(self, current: float) -> None:
        cutoff = current - self._retention_seconds
        expired = [key for key, at in self._claims.items() if at < cutoff]
        for key in expired:
            del self._claims[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._claims)
