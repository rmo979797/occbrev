"""Tests for the admin-receipt notification email sent on every new signup.

Mirrors the structure of test_waitlist_email.py — the admin notification
uses the same Resend pipeline but is plain-text only and goes to the
operator (you), not the supplier. Disabled cleanly when
ADMIN_NOTIFICATION_EMAIL is empty (the default in dev/test).
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from unittest.mock import patch

os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

import email_sender
from main import app


client = TestClient(app)


def _payload(**overrides):
    nonce = uuid.uuid4().hex[:8]
    base = {
        "business_name": "Notify Test Co",
        "category": "caterer",
        "service_area": "central-london",
        "instagram_handle": f"notify_{nonce}",
        "feedback": "Looking forward to it.",
        "ready_to_onboard": True,
        "email": f"notify+{nonce}@example.com",
        "form_loaded_at": time.time() - 10,
        "website": "",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Trigger behaviour — fires on first signup, not on re-submissions
# ---------------------------------------------------------------------------
def test_admin_notification_fires_on_new_signup():
    p = _payload()
    with patch("routes.waitlist.send_admin_signup_notification") as mock_notify:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_notify.assert_called_once()
    kwargs = mock_notify.call_args.kwargs
    assert kwargs["email"] == p["email"]
    assert kwargs["business_name"] == p["business_name"]
    assert kwargs["category"] == "caterer"


def test_admin_notification_skipped_on_resubmission():
    """Same email submitted twice should only ping the admin once."""
    email = f"dup+{uuid.uuid4().hex[:8]}@example.com"
    with patch("routes.waitlist.send_admin_signup_notification") as mock_notify:
        client.post("/api/waitlist/supplier", json=_payload(email=email))
        client.post(
            "/api/waitlist/supplier",
            json=_payload(email=email, business_name="Updated"),
        )
    assert mock_notify.call_count == 1


def test_admin_notification_skipped_for_bot_submission():
    p = _payload(website="http://spam/")
    with patch("routes.waitlist.send_admin_signup_notification") as mock_notify:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_notify.assert_not_called()


def test_admin_notification_skipped_for_disposable_email():
    p = _payload(email=f"x+{uuid.uuid4().hex[:6]}@mailinator.com")
    with patch("routes.waitlist.send_admin_signup_notification") as mock_notify:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_notify.assert_not_called()


# ---------------------------------------------------------------------------
# email_sender behaviour — feature toggle, content, formatting
# ---------------------------------------------------------------------------
def test_no_op_when_admin_email_not_configured(monkeypatch):
    """If ADMIN_NOTIFICATION_EMAIL is empty (default), the function returns
    True without dispatching anything. This is the dev / opt-out path."""
    monkeypatch.setattr(email_sender.settings, "ADMIN_NOTIFICATION_EMAIL", "")
    # If this tried to dispatch we'd see an attempt to import resend; assert
    # it didn't by patching _dispatch and checking it wasn't called.
    with patch("email_sender._dispatch") as mock_dispatch:
        ok = email_sender.send_admin_signup_notification(
            business_name="Test", email="a@b.com", category="caterer",
            category_other=None, service_area="central-london",
            instagram_handle=None, feedback=None, ready_to_onboard=False, ip=None,
        )
    assert ok is True
    mock_dispatch.assert_not_called()


def test_dev_mode_logs_when_admin_email_set_but_no_api_key(monkeypatch, caplog):
    """ADMIN_NOTIFICATION_EMAIL set + RESEND_API_KEY empty = log to stdout,
    don't attempt network."""
    monkeypatch.setattr(
        email_sender.settings, "ADMIN_NOTIFICATION_EMAIL", "ops@example.com"
    )
    monkeypatch.setattr(email_sender.settings, "RESEND_API_KEY", "")
    with caplog.at_level(logging.WARNING, logger="occasions.email"):
        ok = email_sender.send_admin_signup_notification(
            business_name="DevCo", email="user@example.com",
            category="caterer", category_other=None,
            service_area="north-london", instagram_handle="devco",
            feedback="hi", ready_to_onboard=True, ip="203.0.113.1",
        )
    assert ok is True
    # Log should contain the recipient and the supplier's details
    combined = "\n".join(rec.message for rec in caplog.records)
    assert "ops@example.com" in combined
    assert "DevCo" in combined
    assert "user@example.com" in combined


def test_notification_body_includes_category_other_label(monkeypatch):
    """When category == 'other' with a custom label, the receipt should
    show 'other (event lighting)' so the operator sees the user's wording."""
    monkeypatch.setattr(
        email_sender.settings, "ADMIN_NOTIFICATION_EMAIL", "ops@example.com"
    )
    monkeypatch.setattr(email_sender.settings, "RESEND_API_KEY", "re_fake")
    with patch("email_sender._dispatch", return_value=True) as mock_dispatch:
        email_sender.send_admin_signup_notification(
            business_name="LightCo", email="a@b.com",
            category="other", category_other="event lighting",
            service_area="east-london", instagram_handle=None,
            feedback=None, ready_to_onboard=False, ip="1.2.3.4",
        )
    text_body = mock_dispatch.call_args.kwargs["text_body"]
    assert "other (event lighting)" in text_body
    assert "LightCo" in text_body
    assert "1.2.3.4" in text_body


def test_notification_body_handles_optional_fields(monkeypatch):
    """Instagram handle and feedback are optional; empty values render as '-'
    and '(no answer)' respectively — never crash, never blank."""
    monkeypatch.setattr(
        email_sender.settings, "ADMIN_NOTIFICATION_EMAIL", "ops@example.com"
    )
    monkeypatch.setattr(email_sender.settings, "RESEND_API_KEY", "re_fake")
    with patch("email_sender._dispatch", return_value=True) as mock_dispatch:
        email_sender.send_admin_signup_notification(
            business_name="MinCo", email="a@b.com",
            category="caterer", category_other=None,
            service_area="south-london", instagram_handle=None,
            feedback=None, ready_to_onboard=False, ip=None,
        )
    text_body = mock_dispatch.call_args.kwargs["text_body"]
    assert "Instagram:   -" in text_body
    assert "(no answer)" in text_body
    assert "IP:          -" in text_body


def test_notification_failure_returns_false_never_raises(monkeypatch):
    """If Resend errors during admin notification, return False — exactly
    like the supplier confirmation. Signup endpoint must keep working."""
    monkeypatch.setattr(
        email_sender.settings, "ADMIN_NOTIFICATION_EMAIL", "ops@example.com"
    )
    monkeypatch.setattr(email_sender.settings, "RESEND_API_KEY", "re_fake")

    fake_resend = type(
        "FakeResend",
        (),
        {
            "api_key": None,
            "Emails": type(
                "FakeEmails",
                (),
                {"send": staticmethod(lambda params: (_ for _ in ()).throw(
                    RuntimeError("503")
                ))},
            ),
        },
    )
    monkeypatch.setitem(__import__("sys").modules, "resend", fake_resend)

    result = email_sender.send_admin_signup_notification(
        business_name="X", email="a@b.com", category="caterer",
        category_other=None, service_area="west-london",
        instagram_handle=None, feedback=None, ready_to_onboard=False, ip=None,
    )
    assert result is False  # logged failure, not a raised exception
