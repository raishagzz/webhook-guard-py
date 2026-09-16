"""Runtime configuration, loaded from the environment."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from webhook_guard.replay import DEFAULT_TOLERANCE_SECONDS


class Settings(BaseSettings):
    """Settings read from the environment or a local .env file.

    The signing secret has no default. A missing secret raises at startup
    rather than silently accepting a value that could never verify.
    """

    model_config = SettingsConfigDict(
        env_prefix="WEBHOOK_GUARD_",
        env_file=".env",
        extra="ignore",
    )

    signing_secret: str
    replay_tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS


@lru_cache
def get_settings() -> Settings:
    return Settings()
