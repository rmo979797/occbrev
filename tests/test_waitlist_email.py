"""Tests for the confirmation email sent on supplier signup.

The send is fired via FastAPI BackgroundTasks AFTER the response, so it
runs out-of-band in production. ``TestClient`` runs background tasks
synchronously within the request, which is exactly what we want here —
we can assert on what would have been sent without dealing with timing.

Coverage:

* New signup triggers the email
* Re-submission (same email) does NOT re-send (no spam)
* Bot submissions don't trigger the email
* Failed sends never break the signup (the user already saw the
  celebration screen — Resend outage is a backoffice problem, not a
  user problem)
* Dev mode (no RESEND_API_KEY) logs instead of dispatching
* Banner image URL flows through to the HTML when set
* Without a banner URL, the CSS-only fallback header renders
"""
from __future__ import annotations

import os
import time
import uuid
from unittest.mock import patch

import pytest

# Ensure TESTING is on before app import (slowapi inits at import time)
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

import email_sender
from main import app


client = TestClient(app)


def _payload(**overrides):
    nonce = uuid.uuid4().hex[:8]
    base = {
        "business_name": "Bella's Balloons",
        "category": "balloon-artist",
        "service_area": "central-london",
        # Randomised per call so the route's handle-collision defence
        # doesn't reject the second test that runs.
        "instagram_handle": f"bellasballoons_{nonce}",
        "feedback": None,
        "ready_to_onboard": True,
        "email": f"email+{nonce}@example.com",
        "form_loaded_at": time.time() - 10,
        "website": "",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Trigger behaviour
# ---------------------------------------------------------------------------
def test_new_signup_triggers_confirmation_email():
    p = _payload()
    with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_send.assert_called_once()
    kwargs = mock_send.call_args.kwargs
    assert kwargs["to_email"] == p["email"]
    assert kwargs["business_name"] == p["business_name"]
    assert kwargs["category_label"] == "balloon artist"


def test_resubmission_does_not_resend_email():
    """Editing your submission shouldn't spam you with another welcome."""
    email = f"resub+{uuid.uuid4().hex[:8]}@example.com"
    with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
        r1 = client.post("/api/waitlist/supplier", json=_payload(email=email))
        r2 = client.post(
            "/api/waitlist/supplier",
            json=_payload(email=email, business_name="Updated Name"),
        )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert mock_send.call_count == 1, "second submission must not trigger email"


def test_honeypot_submission_does_not_send_email():
    """Bot submissions get a 201 ACK but neither a DB row NOR an email."""
    p = _payload(website="http://spammer.example/")
    with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_send.assert_not_called()


def test_too_fast_submission_does_not_send_email():
    p = _payload(form_loaded_at=time.time() - 0.2)
    with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    mock_send.assert_not_called()


def test_other_category_uses_user_label_in_email():
    """When the user picks 'Other' and types their own label, the email
    should reflect their wording (not the generic "supplier")."""
    p = _payload(category="other", category_other="event lighting")
    with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert mock_send.call_args.kwargs["category_label"] == "event lighting"


# ---------------------------------------------------------------------------
# Failure handling — Resend outage must not break the signup
# ---------------------------------------------------------------------------
def test_resend_sdk_failure_is_caught_inside_sender(monkeypatch, caplog):
    """The whole point of the try/except inside send_waitlist_confirmation
    is that a Resend outage logs an error and returns False — never raises.
    This is what protects the signup endpoint from a third-party failure."""
    import logging
    # Pretend RESEND_API_KEY is set so we actually attempt the send path
    monkeypatch.setattr(email_sender.settings, "RESEND_API_KEY", "re_test_fake")

    # Stub out the resend module's send to blow up the way a real outage would
    fake_resend = type(
        "FakeResend",
        (),
        {
            "api_key": None,
            "Emails": type(
                "FakeEmails",
                (),
                {"send": staticmethod(lambda params: (_ for _ in ()).throw(
                    RuntimeError("503 Service Unavailable")
                ))},
            ),
        },
    )
    monkeypatch.setitem(__import__("sys").modules, "resend", fake_resend)

    with caplog.at_level(logging.ERROR, logger="occasions.email"):
        result = email_sender.send_waitlist_confirmation(
            to_email="user@example.com",
            business_name="Test Co",
            category_label="caterer",
        )
    assert result is False, "outage must surface as a False return, not an exception"
    assert any("failed" in rec.message.lower() for rec in caplog.records)


def test_signup_succeeds_even_if_email_returns_false():
    """If the background task returns False (logged failure), the user
    still sees the success ACK. This is the user-facing contract."""
    p = _payload()
    with patch("routes.waitlist.send_waitlist_confirmation", return_value=False):
        r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert r.json()["success"] is True


# ---------------------------------------------------------------------------
# email_sender module — dev/test fallback + template rendering
# ---------------------------------------------------------------------------
def test_dev_mode_logs_instead_of_sending(caplog):
    """With no RESEND_API_KEY (the test default), send_waitlist_confirmation
    must return True and log — never reach the network."""
    import logging
    with caplog.at_level(logging.WARNING, logger="occasions.email"):
        ok = email_sender.send_waitlist_confirmation(
            to_email="dev@example.com",
            business_name="DevCo",
            category_label="caterer",
        )
    assert ok is True
    assert any("[email:dev]" in rec.message for rec in caplog.records)


def test_html_template_escapes_user_input():
    """Defence in depth: even though business_name is length-capped and
    trimmed at the API layer, the HTML template must escape it. Catches
    a future regression where someone bypasses the API and calls the
    sender directly with raw input."""
    html = email_sender._render_html(
        business_name="<script>alert('xss')</script>",
        category_label="<img src=x onerror=1>",
    )
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror=1>" not in html
    assert "&lt;img" in html


def test_text_template_is_plaintext_only():
    """Plain-text alternative must contain no HTML tags."""
    text = email_sender._render_text(
        business_name="Bella's Balloons",
        category_label="balloon artist",
    )
    assert "<" not in text and ">" not in text
    assert "Bella's Balloons" in text
    assert "balloon artist" in text


def test_banner_url_appears_in_html_when_set(monkeypatch):
    """When EMAIL_BANNER_URL is configured, the template should use it as
    an <img> tag; the CSS-only typographic wordmark should NOT render
    (the supplier-provided logo replaces it).

    Both branches keep the 'Founding Supplier' eyebrow for context — it's
    common to both header variants — so the discriminator is the gold
    serif "Occasions" wordmark, which only appears in the fallback."""
    monkeypatch.setattr(
        email_sender.settings, "EMAIL_BANNER_URL", "https://cdn.example/hero.png"
    )
    html = email_sender._render_html(
        business_name="DevCo", category_label="caterer"
    )
    assert 'src="https://cdn.example/hero.png"' in html
    # Banner branch: no Georgia serif wordmark block
    assert "Georgia,'Times New Roman'" not in html


def test_css_fallback_renders_when_no_banner_url(monkeypatch):
    """Default state (no banner URL): the CSS-only branded header renders
    with the gold wordmark — emails still look polished."""
    monkeypatch.setattr(email_sender.settings, "EMAIL_BANNER_URL", "")
    html = email_sender._render_html(
        business_name="DevCo", category_label="caterer"
    )
    assert "Founding Supplier" in html
    assert "Occasions" in html
    # No <img> at the top — the gold serif wordmark is what readers see.
    assert "<img" not in html.split("Occasions")[0]
    # The Georgia-stack wordmark is the discriminator vs the banner branch.
    assert "Georgia,'Times New Roman'" in html


def test_business_name_falls_back_to_friendly_default():
    """If the upstream caller passes an empty business name (shouldn't
    happen in prod, but worth covering), the email opens with a friendly
    'Hi there,' instead of 'Hi ,'."""
    html = email_sender._render_html(business_name="   ", category_label=None)
    text = email_sender._render_text(business_name="", category_label=None)
    assert "Hi there," in html
    assert "Hi there," in text
