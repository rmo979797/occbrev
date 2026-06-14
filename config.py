"""Isolated config — only what the waitlist deployment needs.

Kept deliberately tiny so the public-facing waitlist box has zero attack
surface beyond what it actually uses. No Stripe keys, no Google API keys,
no JWT secrets, no email-sender creds.
"""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Occasions Waitlist"
    APP_VERSION: str = os.environ.get("APP_VERSION", "1.0.0")
    ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "development")

    # Postgres in prod (Railway provides this), SQLite locally for tests.
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./waitlist.db")

    # Basic-Auth credentials for /api/waitlist/admin. Both must be set in
    # production or the admin endpoint refuses to start; default values are
    # only acceptable in dev/test.
    ADMIN_USER: str = os.environ.get("ADMIN_USER", "admin")
    ADMIN_PASS: str = os.environ.get("ADMIN_PASS", "change-me-in-production")

    # Optional Sentry — only enabled when SENTRY_DSN is set.
    SENTRY_DSN: str = os.environ.get("SENTRY_DSN", "")

    model_config = {"env_file": ".env"}


settings = Settings()
