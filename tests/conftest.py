"""Test-wide fixtures.

Runs BEFORE any test module is imported. Sets the env vars the standalone
waitlist app needs at import time:

* ``TESTING=1`` — relaxes slowapi to a non-blocking limit
* ``ADMIN_USER`` / ``ADMIN_PASS`` — known credentials so admin tests can
  authenticate without a user table

These are sole responsibility of the test runner; production env vars are
set in Railway.
"""
import os
import sys
from pathlib import Path

# Make the project root importable (so `from main import app` works whether
# pytest is invoked from the repo root or inside the tests/ folder).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("TESTING", "1")
os.environ.setdefault("ADMIN_USER", "testadmin")
os.environ.setdefault("ADMIN_PASS", "test-password-do-not-use-in-prod")
os.environ.setdefault("ENVIRONMENT", "development")   # keeps prod-only guards off
# Force a per-process SQLite DB so tests are hermetic and don't tread on a
# locally-created waitlist.db a developer might be using for manual testing.
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_waitlist.db")

# Create the schema. In prod this is Alembic's job, but for tests we skip
# the migration round-trip and ask SQLAlchemy to materialise everything.
from database import Base, engine  # noqa: E402  — imports must come after env vars
from models import WaitlistSignup  # noqa: F401,E402 — registers the table

Base.metadata.create_all(bind=engine)
