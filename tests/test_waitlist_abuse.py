"""Tests for the anti-abuse layer added to the supplier signup endpoint.

These cover the three defences that protect the Resend reputation and the
admin queue from coordinated abuse:

  1. Disposable-email domain blocklist
  2. Per-IP daily quota on new (distinct-email) signups
  3. Instagram handle collision (impersonation) detection

The contract for every defence: silent 201 ACK, no DB write, no confirmation
email, log a WARNING. The attacker can't distinguish a rejection from a real
signup.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from unittest.mock import patch

# Ensure TESTING=1 is in env before route import (the module reads it at
# import time to relax the per-IP cap for the shared 127.0.0.1 in tests).
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

import routes.waitlist as wl
from database import SessionLocal
from main import app
from models import WaitlistSignup


client = TestClient(app)


def _payload(**overrides):
    """Fresh payload — randomised email + handle so the test doesn't trip
    the new anti-impersonation defence from previous tests' writes."""
    nonce = uuid.uuid4().hex[:8]
    base = {
        "business_name": "Acme Events",
        "category": "balloon-artist",
        "service_area": "central-london",
        "instagram_handle": f"acme_{nonce}",
        "ready_to_onboard": True,
        "email": f"abuse+{nonce}@example.com",
        "form_loaded_at": time.time() - 10,
        "website": "",
    }
    base.update(overrides)
    return base


def _count(email: str) -> int:
    db = SessionLocal()
    try:
        return (
            db.query(WaitlistSignup)
            .filter(WaitlistSignup.role == "supplier")
            .filter(WaitlistSignup.email == email)
            .count()
        )
    finally:
        db.close()


# ===========================================================================
# 1. Disposable-email blocklist
# ===========================================================================
class TestDisposableEmailBlocklist:
    def test_mailinator_silently_dropped(self, caplog):
        p = _payload(email=f"junk+{uuid.uuid4().hex[:6]}@mailinator.com")
        with patch("routes.waitlist.send_waitlist_confirmation") as mock_send, \
             caplog.at_level(logging.WARNING, logger="occasions.waitlist"):
            r = client.post("/api/waitlist/supplier", json=p)
        assert r.status_code == 201           # same ACK as a real signup
        assert _count(p["email"]) == 0        # but no row written
        mock_send.assert_not_called()         # and no email sent
        assert any("disposable" in rec.message.lower() for rec in caplog.records)

    def test_guerrillamail_silently_dropped(self):
        p = _payload(email=f"junk+{uuid.uuid4().hex[:6]}@guerrillamail.com")
        r = client.post("/api/waitlist/supplier", json=p)
        assert r.status_code == 201
        assert _count(p["email"]) == 0

    def test_disposable_check_is_case_insensitive(self):
        """An attacker can't bypass with MAILINATOR.COM"""
        p = _payload(email=f"junk+{uuid.uuid4().hex[:6]}@MAILINATOR.COM")
        r = client.post("/api/waitlist/supplier", json=p)
        assert r.status_code == 201
        assert _count(p["email"].lower()) == 0

    def test_real_email_domain_passes(self):
        """Sanity: gmail/outlook/custom domains all sail through."""
        for domain in ["gmail.com", "outlook.com", "occasions.london"]:
            p = _payload(email=f"real+{uuid.uuid4().hex[:6]}@{domain}")
            r = client.post("/api/waitlist/supplier", json=p)
            assert r.status_code == 201
            assert _count(p["email"]) == 1, f"{domain} should NOT be blocked"


# ===========================================================================
# 2. Per-IP daily quota
# ===========================================================================
class TestPerIPDailyQuota:
    def test_quota_blocks_after_threshold(self, monkeypatch):
        """5th signup from the same IP within 24h is silently dropped."""
        # Tighten the cap to 3 for a fast, deterministic test.
        monkeypatch.setattr(wl, "PER_IP_DAILY_NEW_EMAILS", 3)
        ip = f"203.0.113.{uuid.uuid4().int % 250}"  # fresh, unique per run

        with patch("routes.waitlist.send_waitlist_confirmation") as mock_send:
            # First 3 should succeed and trigger confirmation emails
            for i in range(3):
                r = client.post(
                    "/api/waitlist/supplier",
                    headers={"X-Forwarded-For": ip},
                    json=_payload(),
                )
                assert r.status_code == 201, f"signup {i+1} unexpectedly rejected"

            assert mock_send.call_count == 3

            # 4th and 5th: same 201 message, but no row, no email
            for _ in range(2):
                p = _payload()
                r = client.post(
                    "/api/waitlist/supplier",
                    headers={"X-Forwarded-For": ip},
                    json=p,
                )
                assert r.status_code == 201
                assert _count(p["email"]) == 0

            # Total emails sent stays at 3 — the attacker can't relay
            # confirmation spam after hitting the cap.
            assert mock_send.call_count == 3

    def test_quota_does_not_block_resubmissions(self, monkeypatch):
        """Re-submitting the SAME email doesn't burn quota. The cap counts
        distinct emails, not total submissions."""
        monkeypatch.setattr(wl, "PER_IP_DAILY_NEW_EMAILS", 2)
        ip = f"203.0.113.{uuid.uuid4().int % 250}"

        p = _payload()
        for _ in range(5):  # same email, 5 times — should never block
            r = client.post(
                "/api/waitlist/supplier",
                headers={"X-Forwarded-For": ip},
                json=p,
            )
            assert r.status_code == 201
        assert _count(p["email"]) == 1  # one row, upserted

    def test_quota_is_per_ip_not_global(self, monkeypatch):
        """One abusive IP doesn't block legitimate signups from other IPs."""
        monkeypatch.setattr(wl, "PER_IP_DAILY_NEW_EMAILS", 1)

        ip_attacker = f"198.51.100.{uuid.uuid4().int % 250}"
        ip_victim = f"203.0.113.{uuid.uuid4().int % 250}"

        # Attacker exhausts their quota
        r1 = client.post(
            "/api/waitlist/supplier",
            headers={"X-Forwarded-For": ip_attacker},
            json=_payload(),
        )
        p_blocked = _payload()
        r2 = client.post(
            "/api/waitlist/supplier",
            headers={"X-Forwarded-For": ip_attacker},
            json=p_blocked,
        )
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert _count(p_blocked["email"]) == 0  # blocked

        # Real supplier on a different IP is unaffected
        p_real = _payload()
        r3 = client.post(
            "/api/waitlist/supplier",
            headers={"X-Forwarded-For": ip_victim},
            json=p_real,
        )
        assert r3.status_code == 201
        assert _count(p_real["email"]) == 1


# ===========================================================================
# 3. Instagram handle impersonation guard
# ===========================================================================
class TestHandleImpersonationGuard:
    def test_same_handle_with_different_email_silently_dropped(self, caplog):
        """First signup with handle X + email A → written. Second signup
        with handle X + email B → silent ACK, NO row, NO confirmation."""
        handle = f"impersonated_{uuid.uuid4().hex[:8]}"

        # Legit registration first
        p_legit = _payload(instagram_handle=handle)
        r1 = client.post("/api/waitlist/supplier", json=p_legit)
        assert r1.status_code == 201
        assert _count(p_legit["email"]) == 1

        # Impersonation attempt — same handle, different email
        p_imp = _payload(instagram_handle=handle)
        with patch("routes.waitlist.send_waitlist_confirmation") as mock_send, \
             caplog.at_level(logging.WARNING, logger="occasions.waitlist"):
            r2 = client.post("/api/waitlist/supplier", json=p_imp)

        assert r2.status_code == 201
        assert _count(p_imp["email"]) == 0
        mock_send.assert_not_called()
        assert any("impersonation" in rec.message.lower() for rec in caplog.records)

    def test_same_email_can_update_their_own_handle_unblocked(self):
        """The defence must NOT block the legit "same person updates their
        own row" path. Same email + same handle = upsert, no false positive."""
        nonce = uuid.uuid4().hex[:8]
        email = f"owner+{nonce}@example.com"
        handle = f"owner_{nonce}"

        p1 = _payload(email=email, instagram_handle=handle, business_name="First")
        p2 = _payload(email=email, instagram_handle=handle, business_name="Second")
        r1 = client.post("/api/waitlist/supplier", json=p1)
        r2 = client.post("/api/waitlist/supplier", json=p2)
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert _count(email) == 1  # upserted, not duplicated

        # And the business name was updated
        db = SessionLocal()
        try:
            row = db.query(WaitlistSignup).filter(WaitlistSignup.email == email).first()
            assert row.business_name == "Second"
        finally:
            db.close()

    def test_no_handle_means_no_collision_check(self):
        """If the user didn't provide a handle, the defence is bypassed —
        we'd otherwise have a lot of false positives on NULL == NULL."""
        # First signup — no handle
        p1 = _payload(instagram_handle=None)
        r1 = client.post("/api/waitlist/supplier", json=p1)
        assert r1.status_code == 201
        assert _count(p1["email"]) == 1

        # Second signup — also no handle, different email — must still go through
        p2 = _payload(instagram_handle=None)
        r2 = client.post("/api/waitlist/supplier", json=p2)
        assert r2.status_code == 201
        assert _count(p2["email"]) == 1


# ===========================================================================
# 4. Cross-defence: no information leak
# ===========================================================================
class TestNoInfoLeak:
    def test_all_rejection_paths_return_identical_response(self, monkeypatch):
        """The response body for every rejection branch (honeypot, timing,
        disposable, IP quota, handle collision) must be byte-identical to
        a real success. Otherwise an attacker can binary-search the rules."""
        monkeypatch.setattr(wl, "PER_IP_DAILY_NEW_EMAILS", 1)
        responses = []

        # Real success (reference)
        responses.append(client.post("/api/waitlist/supplier", json=_payload()).json())

        # Honeypot
        responses.append(client.post(
            "/api/waitlist/supplier", json=_payload(website="http://spam/")
        ).json())

        # Too fast
        responses.append(client.post(
            "/api/waitlist/supplier", json=_payload(form_loaded_at=time.time() - 0.1)
        ).json())

        # Disposable email
        responses.append(client.post(
            "/api/waitlist/supplier",
            json=_payload(email=f"x+{uuid.uuid4().hex[:6]}@mailinator.com"),
        ).json())

        # IP quota (set to 1, so the 2nd signup from this IP is blocked)
        ip = f"203.0.113.{uuid.uuid4().int % 250}"
        client.post(
            "/api/waitlist/supplier",
            headers={"X-Forwarded-For": ip},
            json=_payload(),
        )
        responses.append(client.post(
            "/api/waitlist/supplier",
            headers={"X-Forwarded-For": ip},
            json=_payload(),
        ).json())

        # Handle collision
        h = f"taken_{uuid.uuid4().hex[:8]}"
        client.post("/api/waitlist/supplier", json=_payload(instagram_handle=h))
        responses.append(client.post(
            "/api/waitlist/supplier", json=_payload(instagram_handle=h)
        ).json())

        # All six bodies must be byte-identical
        assert len(set(map(repr, responses))) == 1, (
            f"Response-body leak across rejection branches: {responses}"
        )
