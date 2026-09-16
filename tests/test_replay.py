"""Replay-window enforcement: fresh, expired, future-dated, and boundary cases."""

import time

import pytest

from webhook_guard.replay import (
    DEFAULT_TOLERANCE_SECONDS,
    ReplayError,
    parse_timestamp,
    verify_timestamp,
)

NOW = 1757952000


def test_accepts_a_current_delivery():
    verify_timestamp(str(NOW), now=NOW)


def test_accepts_a_delivery_inside_the_window():
    verify_timestamp(str(NOW - 120), now=NOW)


def test_rejects_a_delivery_older_than_the_window():
    with pytest.raises(ReplayError, match="outside"):
        verify_timestamp(str(NOW - 600), now=NOW)


def test_rejects_a_delivery_stamped_far_in_the_future():
    with pytest.raises(ReplayError, match="future"):
        verify_timestamp(str(NOW + 600), now=NOW)


def test_tolerates_small_forward_clock_skew():
    verify_timestamp(str(NOW + 30), now=NOW)


@pytest.mark.parametrize(
    "offset",
    [DEFAULT_TOLERANCE_SECONDS, -DEFAULT_TOLERANCE_SECONDS],
    ids=["oldest-accepted", "furthest-future-accepted"],
)
def test_accepts_the_window_boundary(offset):
    verify_timestamp(str(NOW - offset), now=NOW)


@pytest.mark.parametrize(
    "offset",
    [DEFAULT_TOLERANCE_SECONDS + 1, -(DEFAULT_TOLERANCE_SECONDS + 1)],
    ids=["one-second-too-old", "one-second-too-future"],
)
def test_rejects_one_second_past_the_boundary(offset):
    with pytest.raises(ReplayError):
        verify_timestamp(str(NOW - offset), now=NOW)


def test_honours_a_custom_tolerance():
    verify_timestamp(str(NOW - 45), tolerance_seconds=60, now=NOW)
    with pytest.raises(ReplayError):
        verify_timestamp(str(NOW - 90), tolerance_seconds=60, now=NOW)


@pytest.mark.parametrize(
    "value",
    ["", "not-a-number", "1757952000.5", " "],
    ids=["empty", "non-numeric", "float", "whitespace"],
)
def test_rejects_unparseable_timestamps(value):
    with pytest.raises(ReplayError):
        parse_timestamp(value)


def test_uses_the_wall_clock_when_no_time_is_injected():
    verify_timestamp(str(int(time.time())))
