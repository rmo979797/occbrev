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

    # Email — transactional confirmation sent after a successful waitlist
    # signup. If RESEND_API_KEY is empty (e.g. dev / tests) the sender
    # logs the email to stdout instead of dispatching. The send is fired
    # in the background by the signup route so a Resend outage never
    # blocks form submission.
    RESEND_API_KEY: str = os.environ.get("RESEND_API_KEY", "")
    EMAIL_FROM: str = os.environ.get("EMAIL_FROM", "hello@occasions.london")
    EMAIL_FROM_NAME: str = os.environ.get("EMAIL_FROM_NAME", "Occasions")
    EMAIL_REPLY_TO: str = os.environ.get("EMAIL_REPLY_TO", "hello@occasions.london")
    # Optional hero image at the top of the email. If unset, the email
    # falls back to a CSS-only branded header. Drop a 1200x300 PNG/JPG
    # at any public URL (e.g. https://occasions.london/static/email/banner.png)
    # and point this env var at it.
    EMAIL_BANNER_URL: str = os.environ.get("EMAIL_BANNER_URL", "")

    model_config = {"env_file": ".env"}


settings = Settings()
