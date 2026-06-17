"""Tests for the supplier multi-area feature.

Suppliers often work across more than one London zone (a florist who
delivers everywhere, a venue stylist who travels). The form now accepts
a list of service-area slugs; legacy clients that still send a single
string are coerced transparently.

Covers:

* a list of areas is accepted and stored as a comma-joined string on
  the existing 'service_area' column (no migration needed)
* a single-string payload (legacy client) is coerced to a one-item list
* duplicate slugs are collapsed, order preserved
* unknown slugs return 422 (not silently dropped)
* empty list returns 422 ("pick at least one")
* the admin notification reflects a multi-area pick
* the 'all London zones' shorthand triggers in the admin email when all
  five inner zones are picked
"""
from __future__ import annotations

import os
import time
import uuid

# Set BEFORE importing the app so slowapi initialises in TESTING mode.
os.environ["TESTING"] = "1"

from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import WaitlistSignup


client = TestClient(app)


def _payload(**overrides):
    nonce = uuid.uuid4().hex[:8]
    base = {
        "business_name": "Multi-Area Supplier",
        "category": "florist",
        "service_area": ["central-london", "north-london"],
        "instagram_handle": f"@area_{nonce}",
        "email": f"area+{nonce}@example.com",
        "form_loaded_at": time.time() - 10,
        "website": "",
    }
    base.update(overrides)
    return base


def _row(email: str) -> WaitlistSignup:
    db = SessionLocal()
    try:
        return (
            db.query(WaitlistSignup)
            .filter(WaitlistSignup.role == "supplier")
            .filter(WaitlistSignup.email == email)
            .first()
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------
def test_two_areas_persist_comma_joined():
    p = _payload(service_area=["central-london", "west-london"])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _row(p["email"]).service_area == "central-london,west-london"


def test_single_area_string_legacy_client_coerced_to_list():
    """A pre-multi-select client posting service_area as a string MUST
    still be accepted — keeps backward compatibility with anyone who
    integrated against the previous schema."""
    p = _payload()
    p["service_area"] = "central-london"
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _row(p["email"]).service_area == "central-london"


def test_all_six_areas_persist():
    p = _payload(service_area=[
        "central-london", "north-london", "south-london",
        "east-london", "west-london", "outside-london",
    ])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    stored = _row(p["email"]).service_area
    for slug in p["service_area"]:
        assert slug in stored


# ---------------------------------------------------------------------------
# De-dup + validation
# ---------------------------------------------------------------------------
def test_duplicate_areas_collapsed():
    p = _payload(service_area=["central-london", "central-london"])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _row(p["email"]).service_area == "central-london"


def test_unknown_area_slug_returns_422():
    p = _payload(service_area=["mars"])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_empty_area_list_returns_422():
    p = _payload(service_area=[])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_area_list_over_cap_returns_422():
    """6 areas is the legitimate maximum (one per chip). A tampered
    payload exceeding that must 422, not silently truncate."""
    p = _payload(service_area=[
        "central-london", "north-london", "south-london",
        "east-london", "west-london", "outside-london",
        "central-london",  # 7th
    ])
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_non_list_non_string_area_returns_422():
    p = _payload()
    p["service_area"] = {"nope": True}
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Admin email
# ---------------------------------------------------------------------------
def test_admin_email_receives_area_list():
    p = _payload(service_area=["central-london", "east-london"])
    with patch("routes.waitlist.send_admin_signup_notification") as mock_admin:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    kwargs = mock_admin.call_args.kwargs
    assert kwargs.get("service_areas") == ["central-london", "east-london"]


def test_admin_email_body_collapses_all_london_zones():
    """When the supplier picks every inner London zone, the receipt
    should read 'all London' instead of listing 5 slugs — saves the
    operator a beat of mental counting."""
    from email_sender import send_admin_signup_notification
    from config import settings

    original_key = settings.RESEND_API_KEY
    original_admin = settings.ADMIN_NOTIFICATION_EMAIL
    try:
        settings.RESEND_API_KEY = ""
        settings.ADMIN_NOTIFICATION_EMAIL = "ops@example.com"
        with patch("email_sender.logger") as mock_logger:
            ok = send_admin_signup_notification(
                business_name="Everywhere Co",
                email="all@example.com",
                category="florist",
                category_other=None,
                secondary_categories=[],
                service_areas=[
                    "central-london", "north-london", "south-london",
                    "east-london", "west-london",
                ],
                instagram_handle=None,
                feedback=None,
                ready_to_onboard=True,
                ip=None,
            )
            assert ok is True
            joined = "\n".join(
                str(c.args) for c in mock_logger.warning.call_args_list
            )
            assert "all London" in joined
            # And we should NOT enumerate the five slugs alongside it.
            assert "central-london, north-london" not in joined
    finally:
        settings.RESEND_API_KEY = original_key
        settings.ADMIN_NOTIFICATION_EMAIL = original_admin


def test_admin_email_body_appends_outside_london_to_all_london():
    """If the supplier ticked all 5 inner zones AND Outside London,
    we should read 'all London + outside-london' — the shorthand still
    applies but the non-London signal isn't lost."""
    from email_sender import send_admin_signup_notification
    from config import settings

    original_key = settings.RESEND_API_KEY
    original_admin = settings.ADMIN_NOTIFICATION_EMAIL
    try:
        settings.RESEND_API_KEY = ""
        settings.ADMIN_NOTIFICATION_EMAIL = "ops@example.com"
        with patch("email_sender.logger") as mock_logger:
            send_admin_signup_notification(
                business_name="Truly Everywhere",
                email="t@example.com",
                category="florist",
                category_other=None,
                secondary_categories=[],
                service_areas=[
                    "central-london", "north-london", "south-london",
                    "east-london", "west-london", "outside-london",
                ],
                instagram_handle=None,
                feedback=None,
                ready_to_onboard=True,
                ip=None,
            )
            joined = "\n".join(
                str(c.args) for c in mock_logger.warning.call_args_list
            )
            assert "all London + outside-london" in joined
    finally:
        settings.RESEND_API_KEY = original_key
        settings.ADMIN_NOTIFICATION_EMAIL = original_admin
