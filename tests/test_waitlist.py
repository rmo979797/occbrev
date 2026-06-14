"""Security & behaviour tests for the waitlist endpoints.

Covers the anti-abuse posture documented in routes/waitlist.py:

* honeypot field silently absorbs bot submissions
* too-fast submissions (timing-based bot detection) are silently dropped
* allow-listed categories / areas / event types — anything else 422
* email is normalised to lowercase, idempotent upsert
* re-submission with the same (role, email) updates, not duplicates
* admin endpoint is protected
* response messages never leak whether an email is new or existing

These tests do NOT exercise rate-limiting end-to-end (TESTING=1 sets
slowapi to a non-blocking limit); rate-limit correctness is a separate
concern covered by the existing security suite.
"""
from __future__ import annotations

import os
import time
import uuid

import pytest

# Set BEFORE importing the app so slowapi initialises in TESTING mode.
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import WaitlistSignup


client = TestClient(app)


def _supplier_payload(**overrides):
    base = {
        "business_name": "Bella's Balloons",
        "category": "balloon",
        "service_area": "central-london",
        "instagram_handle": "@bellasballoons",
        "feedback": "Weekly bookings without chasing.",
        "ready_to_onboard": True,
        "email": f"sup+{uuid.uuid4().hex[:8]}@example.com",
        # Pretend the form was rendered 10 seconds ago — well over the
        # MIN_SUBMIT_SECONDS threshold, so we pass the bot timing check.
        "form_loaded_at": time.time() - 10,
        "website": "",  # honeypot empty == human
    }
    base.update(overrides)
    return base


def _count(role: str, email: str) -> int:
    db = SessionLocal()
    try:
        return (
            db.query(WaitlistSignup)
            .filter(WaitlistSignup.role == role)
            .filter(WaitlistSignup.email == email)
            .count()
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------
def test_supplier_signup_writes_one_row():
    p = _supplier_payload()
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    body = r.json()
    assert body["success"] is True
    assert "on the list" in body["message"].lower()
    assert _count("supplier", p["email"]) == 1


def test_email_is_normalised_to_lowercase():
    email = f"MixedCase+{uuid.uuid4().hex[:8]}@Example.COM"
    r = client.post("/api/waitlist/supplier", json=_supplier_payload(email=email))
    assert r.status_code == 201
    # Stored lowercase
    assert _count("supplier", email.lower()) == 1
    assert _count("supplier", email) == 0  # not the original mixed-case


# ---------------------------------------------------------------------------
# Anti-bot defences (the headline reason this code exists)
# ---------------------------------------------------------------------------
def test_honeypot_field_silently_drops_submission():
    """A bot that fills the honeypot gets a 201 ACK — but nothing is written.
    The response must be indistinguishable from a real signup so the bot
    doesn't learn what the trap was called."""
    p = _supplier_payload(website="http://spammer.example/")
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    body = r.json()
    assert body["success"] is True
    # Crucially, nothing landed in the DB
    assert _count("supplier", p["email"]) == 0


def test_too_fast_submission_silently_dropped():
    """A submission within MIN_SUBMIT_SECONDS of the page render is bot-like."""
    p = _supplier_payload(form_loaded_at=time.time() - 0.2)  # 200ms
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _count("supplier", p["email"]) == 0


def test_future_form_loaded_at_treated_as_bot():
    """A clock-skewed or tampered form_loaded_at in the future is suspicious."""
    p = _supplier_payload(form_loaded_at=time.time() + 60)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _count("supplier", p["email"]) == 0


def test_missing_form_loaded_at_still_allowed():
    """Edge case: very old browser or JS-disabled. We trust it through (the
    honeypot still catches the obvious bots) so we don't punish humans."""
    p = _supplier_payload(form_loaded_at=None)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _count("supplier", p["email"]) == 1


# ---------------------------------------------------------------------------
# Validation — allow-listed enums
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("field,bad_value", [
    ("category", "<script>alert(1)</script>"),
    ("category", "totally-fake"),
    ("service_area", "mars"),
])
def test_supplier_rejects_invalid_enum_values(field, bad_value):
    p = _supplier_payload(**{field: bad_value})
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422, r.text


def test_instagram_handle_strict_charset():
    """Instagram handles must match [A-Za-z0-9._] — anything else is 422."""
    p = _supplier_payload(instagram_handle="bella'; DROP TABLE users--")
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_instagram_handle_strips_at_sign():
    email = f"sup+{uuid.uuid4().hex[:8]}@example.com"
    p = _supplier_payload(email=email, instagram_handle="@goodhandle")
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    db = SessionLocal()
    try:
        row = db.query(WaitlistSignup).filter(WaitlistSignup.email == email).first()
        assert row.instagram_handle == "goodhandle"
    finally:
        db.close()


def test_oversized_business_name_rejected():
    p = _supplier_payload(business_name="X" * 200)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_oversized_feedback_rejected():
    p = _supplier_payload(feedback="X" * 1000)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_invalid_email_rejected():
    p = _supplier_payload(email="not-an-email")
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Idempotency — re-submission updates, no duplicates, no info leak
# ---------------------------------------------------------------------------
def test_resubmit_updates_existing_row():
    email = f"resub+{uuid.uuid4().hex[:8]}@example.com"
    r1 = client.post(
        "/api/waitlist/supplier",
        json=_supplier_payload(email=email, business_name="First Name"),
    )
    r2 = client.post(
        "/api/waitlist/supplier",
        json=_supplier_payload(email=email, business_name="Second Name"),
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    # Same success message both times — no "already on the list" leak
    assert r1.json()["message"] == r2.json()["message"]
    # Only ONE row, with the updated name
    assert _count("supplier", email) == 1
    db = SessionLocal()
    try:
        row = db.query(WaitlistSignup).filter(WaitlistSignup.email == email).first()
        assert row.business_name == "Second Name"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Admin endpoint
# ---------------------------------------------------------------------------
def test_admin_endpoint_requires_admin():
    r = client.get("/api/waitlist/admin")
    assert r.status_code in (401, 403)


def test_admin_endpoint_with_admin_token_works():
    # Standalone deployment uses HTTP Basic Auth set via env vars
    # (see tests/conftest.py for the test credentials).
    r = client.get(
        "/api/waitlist/admin",
        auth=("testadmin", "test-password-do-not-use-in-prod"),
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------------------------------------------------------------------------
# IP + UA capture
# ---------------------------------------------------------------------------
def test_ip_and_user_agent_captured():
    p = _supplier_payload()
    r = client.post(
        "/api/waitlist/supplier",
        headers={
            "X-Forwarded-For": "203.0.113.42",
            "User-Agent": "WaitlistTestBot/1.0",
        },
        json=p,
    )
    assert r.status_code == 201
    db = SessionLocal()
    try:
        row = db.query(WaitlistSignup).filter(WaitlistSignup.email == p["email"]).first()
        assert row.ip == "203.0.113.42"
        assert row.user_agent == "WaitlistTestBot/1.0"
    finally:
        db.close()
