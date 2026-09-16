"""Idempotency store: repeat delivery, concurrency, expiry, and release."""

import threading

import pytest

from webhook_guard.idempotency import InMemoryIdempotencyStore


def test_first_claim_wins():
    store = InMemoryIdempotencyStore()
    assert store.claim("evt_123") is True


def test_repeat_delivery_does_not_win_the_claim():
    store = InMemoryIdempotencyStore()
    store.claim("evt_123")
    assert store.claim("evt_123") is False


def test_distinct_events_each_win():
    store = InMemoryIdempotencyStore()
    assert store.claim("evt_123") is True
    assert store.claim("evt_456") is True


def test_release_allows_a_retry_to_win():
    store = InMemoryIdempotencyStore()
    store.claim("evt_123")
    store.release("evt_123")
    assert store.claim("evt_123") is True


def test_release_of_an_unknown_event_is_a_no_op():
    store = InMemoryIdempotencyStore()
    store.release("evt_never_seen")


def test_rejects_an_empty_event_id():
    store = InMemoryIdempotencyStore()
    with pytest.raises(ValueError):
        store.claim("")


def test_claims_expire_after_the_retention_window():
    clock = {"t": 1000.0}
    store = InMemoryIdempotencyStore(retention_seconds=60, now=lambda: clock["t"])

    assert store.claim("evt_123") is True
    clock["t"] = 1030.0
    assert store.claim("evt_123") is False

    clock["t"] = 1100.0
    assert store.claim("evt_123") is True


def test_expiry_bounds_store_growth():
    clock = {"t": 1000.0}
    store = InMemoryIdempotencyStore(retention_seconds=60, now=lambda: clock["t"])

    for i in range(50):
        store.claim(f"evt_{i}")
    assert len(store) == 50

    clock["t"] = 2000.0
    store.claim("evt_new")
    assert len(store) == 1


def test_concurrent_deliveries_produce_exactly_one_winner():
    store = InMemoryIdempotencyStore()
    results: list[bool] = []
    lock = threading.Lock()
    start = threading.Barrier(16)

    def attempt() -> None:
        start.wait()
        won = store.claim("evt_race")
        with lock:
            results.append(won)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 15
