"""Smoke test: the package is importable from the installed distribution."""

import webhook_guard


def test_package_is_importable():
    assert webhook_guard.__name__ == "webhook_guard"
