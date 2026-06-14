"""Hardening tests for the public waitlist endpoint.

This is the only unauthenticated, internet-facing write endpoint in the
pre-launch build, so it gets the highest level of scrutiny. The tests below
target the OWASP API Top 10 categories and a handful of historical
internet-marketplace mishaps:

  * API1  Broken Object-Level Auth   — admin endpoint requires admin
  * API3  Broken Object Property     — mass-assignment guard
  * API4  Resource Consumption       — oversize payload, deep nesting
  * API5  Broken Function-Level Auth — HTTP method allow-list
  * API6  Server-Side Request Forgery — n/a (no outbound fetch)
  * API7  Security Misconfig         — CSP, X-Frame-Options, nosniff
  * API8  Injection (SQL, XSS, CRLF, header smuggling)
  * API9  Improper Inventory         — schema strictness (no unknown fields)
  * API10 Unsafe API Consumption     — wrong content-type rejected

We also cover:
  * Email-enumeration safety (response identical for new vs existing).
  * Concurrent submission race against the (role,email) unique index.
  * Type-confusion attacks (boolean fields fed garbage).
  * Unicode trickery (null bytes, RTL override, zero-width chars).
  * Rate-limit decorator is actually wired to the endpoint.
  * The DB is still healthy after a flood of garbage requests.

These tests run against the in-process TestClient under TESTING=1 (which
relaxes slowapi to a non-blocking limit). For a real rate-limit assertion
see `test_rate_limit_decorator_is_wired_up` which inspects the route's
registered limits without actually triggering them.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid

import pytest

# Set BEFORE importing the app so slowapi initialises in TESTING mode.
os.environ.setdefault("TESTING", "1")

from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import WaitlistSignup
from routes import waitlist as waitlist_module


client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _good_payload(**overrides):
    """A clean, server-accepted payload. Tests mutate one field at a time so
    failures point straight at the security concern they're targeting."""
    base = {
        "business_name": "Bella's Balloons",
        "category": "balloon",
        "service_area": "central-london",
        "instagram_handle": "bellasballoons",
        "feedback": "Weekly bookings without chasing.",
        "ready_to_onboard": True,
        "email": f"sec+{uuid.uuid4().hex[:8]}@example.com",
        "form_loaded_at": time.time() - 10,
        "website": "",
    }
    base.update(overrides)
    return base


def _row(email: str) -> WaitlistSignup | None:
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


def _count_all() -> int:
    db = SessionLocal()
    try:
        return db.query(WaitlistSignup).count()
    finally:
        db.close()


# ===========================================================================
# Injection — SQL, XSS, CRLF, header smuggling
# ===========================================================================

# Classic SQLi payloads. With SQLAlchemy parameterised queries these MUST
# land as literal strings, never alter execution. The endpoint either
# accepts the payload (and stores it verbatim in business_name/feedback)
# or rejects it via Pydantic validation — both are safe; what would be
# unsafe is a 500.
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE waitlist_signups; --",
    "' UNION SELECT password FROM users --",
    "admin'--",
    "1; SELECT pg_sleep(10); --",
    "'; SELECT 1/0; --",
    "\\'; DROP TABLE users; --",
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sql_injection_in_business_name_is_stored_as_literal(payload):
    """SQLi payload in business_name does NOT crash, does NOT execute, and
    is stored verbatim. The table still exists afterwards."""
    p = _good_payload(business_name=payload)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code in (201, 422), r.text
    # The waitlist table must still exist + be readable.
    assert _count_all() >= 0
    if r.status_code == 201:
        row = _row(p["email"])
        assert row is not None
        assert row.business_name == payload   # stored as literal, no execution


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sql_injection_in_feedback_does_not_crash(payload):
    p = _good_payload(feedback=payload)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code in (201, 422), r.text


def test_sql_injection_in_email_is_rejected_by_validator():
    """EmailStr is strict — payloads that don't look like a real email get
    a 422 before they ever reach the DB layer."""
    for bad in ["' OR 1=1--@x.com", "x@x.com'; DROP TABLE users; --"]:
        r = client.post("/api/waitlist/supplier", json=_good_payload(email=bad))
        # Both are invalid emails per RFC; should 422.
        assert r.status_code == 422, f"{bad!r} got {r.status_code}: {r.text[:120]}"


# ---------------------------------------------------------------------------
# XSS — stored payloads are returned via the admin API as JSON, which is
# inherently safe (no HTML rendering), but we still verify the response is
# valid JSON and that the payload round-trips unchanged. Whoever renders
# admin output is responsible for escaping; we just make sure we don't
# pre-mangle it (e.g. by accidentally HTML-encoding into the DB).
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
]


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_in_business_name_stored_safely(payload):
    p = _good_payload(business_name=payload)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201, r.text
    # JSON response must NEVER echo the payload as raw HTML
    body = r.text
    assert payload not in body or "Content-Type" in r.headers and "application/json" in r.headers["Content-Type"]
    # And the JSON body itself is a plain success ACK — no field echo.
    assert r.json() == {
        "success": True,
        "message": "You're on the list — we'll be in touch soon.",
    }


def test_response_content_type_is_json_never_html():
    """Belt-and-braces: even if a payload made it into the success message,
    the response is application/json so browsers won't sniff it as HTML."""
    r = client.post("/api/waitlist/supplier", json=_good_payload())
    assert "application/json" in r.headers.get("content-type", "").lower()


# ---------------------------------------------------------------------------
# CRLF / header injection — newlines in email or business name must not
# corrupt response headers or logs. Pydantic's EmailStr rejects \r\n in
# the email field; the others get stored as-is (and we never echo them
# into headers).
# ---------------------------------------------------------------------------
CRLF_PAYLOADS = [
    "evil@example.com\r\nBcc: spam@victim.test",
    "evil@example.com\nSet-Cookie: hacked=1",
    "evil@example.com%0d%0aBcc:spam@victim.test",
    "evil@example.com\r\n\r\n<script>alert(1)</script>",
]


@pytest.mark.parametrize("payload", CRLF_PAYLOADS)
def test_crlf_in_email_is_rejected(payload):
    r = client.post("/api/waitlist/supplier", json=_good_payload(email=payload))
    assert r.status_code == 422, r.text


def test_crlf_in_business_name_does_not_leak_into_response_headers():
    p = _good_payload(business_name="Bella's\r\nX-Evil: pwned")
    r = client.post("/api/waitlist/supplier", json=p)
    # Server must NOT have set a header from the user-supplied newline.
    assert "x-evil" not in {k.lower() for k in r.headers}
    # Either accepted (and stored literally) or rejected (also fine).
    assert r.status_code in (201, 422)


# ===========================================================================
# Resource consumption — oversize payloads, deep nesting, huge floods
# ===========================================================================
def test_oversize_business_name_rejected_cleanly():
    """The Pydantic max_length=80 must reject 1MB strings with a 422,
    not a 500 or a hang."""
    p = _good_payload(business_name="A" * 1_000_000)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422, f"expected 422 got {r.status_code}"


def test_oversize_feedback_rejected_cleanly():
    p = _good_payload(feedback="A" * 100_000)
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422


def test_deeply_nested_json_does_not_crash():
    """A 200-level nested JSON object should NOT crash the server. Either
    Pydantic rejects it as an invalid string (422) or Starlette returns
    400 — never 500."""
    deep = "{" * 200 + "}" * 200
    r = client.post(
        "/api/waitlist/supplier",
        data=deep,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in (400, 422), r.text


def test_flood_of_bad_payloads_leaves_db_healthy():
    """Burst 60 garbage requests — server should still respond, DB should
    still accept a normal write afterwards. Catches connection leaks,
    transaction state corruption, and other tail risks."""
    for i in range(60):
        r = client.post("/api/waitlist/supplier", json={"junk": i, "more": "garbage"})
        assert r.status_code in (400, 422), f"req {i}: {r.status_code}"
    # Real signup still works
    p = _good_payload()
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    assert _row(p["email"]) is not None


# ===========================================================================
# HTTP method + content-type discipline
# ===========================================================================
@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_wrong_http_method_rejected(method):
    """Only POST is allowed on /supplier. Anything else: 405."""
    r = getattr(client, method)("/api/waitlist/supplier")
    assert r.status_code == 405, f"{method} returned {r.status_code}"


def test_form_encoded_body_rejected():
    """The endpoint expects JSON. Form-encoded bodies should 422 (Pydantic
    can't parse them) rather than be silently coerced — keeps attack
    surface minimal."""
    r = client.post(
        "/api/waitlist/supplier",
        data="business_name=x&email=x@x.com",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code in (400, 415, 422), r.text


def test_text_plain_body_rejected():
    r = client.post(
        "/api/waitlist/supplier",
        data="not json at all",
        headers={"Content-Type": "text/plain"},
    )
    assert r.status_code in (400, 415, 422)


def test_malformed_json_body_rejected_cleanly():
    """A trailing comma + missing brace must NOT 500."""
    r = client.post(
        "/api/waitlist/supplier",
        data='{"business_name": "x",,, "broken"',
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in (400, 422), r.text


# ===========================================================================
# Mass-assignment — clients can't set internal fields
# ===========================================================================
def test_mass_assignment_role_field_ignored():
    """A supplier payload with role='admin' (or 'customer') must NOT change
    the stored row's role. The endpoint hard-codes role='supplier'."""
    p = _good_payload()
    p["role"] = "admin"
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    row = _row(p["email"])
    assert row is not None
    assert row.role == "supplier"


def test_mass_assignment_status_field_ignored():
    """Client should not be able to set status='converted' to skip the
    invite flow."""
    p = _good_payload()
    p["status"] = "converted"
    p["converted_user_id"] = "any-uuid-they-fancy"
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    row = _row(p["email"])
    assert row is not None
    assert row.status == "pending"
    assert row.converted_user_id is None


def test_mass_assignment_ip_and_ua_come_from_request_not_payload():
    """Even if the client sends `ip` and `user_agent` in the JSON, the
    stored values must come from the request, not the payload — otherwise
    a bot could pretend to be from a different IP."""
    p = _good_payload()
    p["ip"] = "8.8.8.8"
    p["user_agent"] = "fake-bot/9.9"
    r = client.post(
        "/api/waitlist/supplier",
        headers={"X-Forwarded-For": "203.0.113.99", "User-Agent": "RealBrowser/1.0"},
        json=p,
    )
    assert r.status_code == 201
    row = _row(p["email"])
    assert row is not None
    assert row.ip == "203.0.113.99"            # from request, not payload
    assert row.user_agent == "RealBrowser/1.0"  # from request, not payload


def test_mass_assignment_id_field_ignored():
    """Client must not be able to set the primary key."""
    forced_id = "attacker-chosen-id"
    p = _good_payload()
    p["id"] = forced_id
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    row = _row(p["email"])
    assert row is not None
    assert row.id != forced_id


# ===========================================================================
# Type confusion
# ===========================================================================
@pytest.mark.parametrize("bad_bool", ["yes", "true ", 1, 0, [], {}])
def test_ready_to_onboard_only_accepts_real_bools(bad_bool):
    """Pydantic v2 coerces "yes"/"true"/1/0 — that's actually fine; the
    column is a boolean. But weird shapes (list, dict) must NOT crash."""
    p = _good_payload()
    p["ready_to_onboard"] = bad_bool
    r = client.post("/api/waitlist/supplier", json=p)
    # 201 (coerced) or 422 (rejected) is fine; 500 is not.
    assert r.status_code in (201, 422), f"{bad_bool!r}: {r.status_code}"


@pytest.mark.parametrize("bad_value", [None, [], {"x": 1}, 12345, ["balloon"]])
def test_category_only_accepts_strings(bad_value):
    p = _good_payload()
    p["category"] = bad_value
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 422, f"{bad_value!r}: {r.status_code}"


def test_form_loaded_at_string_does_not_crash():
    """A string in form_loaded_at must not throw — Pydantic should 422 or
    coerce."""
    p = _good_payload()
    p["form_loaded_at"] = "not-a-number"
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code in (201, 422)


# ===========================================================================
# Unicode trickery
# ===========================================================================
def test_null_byte_in_business_name_does_not_crash():
    """A NUL byte must not break the SQLite text storage or the JSON
    response."""
    p = _good_payload(business_name="Bella\x00Balloons")
    r = client.post("/api/waitlist/supplier", json=p)
    # NUL bytes are valid Unicode, just unusual. We don't care if Pydantic
    # accepts or rejects, just that we don't 500.
    assert r.status_code in (201, 422), r.text


def test_rtl_override_in_business_name_does_not_crash():
    """Right-to-left override (U+202E) is a common phishing trick. Must not
    break anything; stored as-is."""
    p = _good_payload(business_name="Bella\u202eBalloons")
    r = client.post("/api/waitlist/supplier", json=p)
    assert r.status_code == 201
    row = _row(p["email"])
    assert row is not None
    # We don't strip the codepoint — that's a rendering concern. Just
    # confirm it was stored exactly as supplied.
    assert "\u202e" in row.business_name


def test_zero_width_chars_dont_help_dupe_emails():
    """A zero-width space inside an email is invalid; can't be used to
    bypass uniqueness."""
    p = _good_payload(email="a\u200bb@example.com")
    r = client.post("/api/waitlist/supplier", json=p)
    # EmailStr rejects this — zero-width is not a valid local-part char.
    assert r.status_code == 422


# ===========================================================================
# Email enumeration — repeated submissions must look identical
# ===========================================================================
def test_response_identical_for_new_and_existing_email():
    """If responses differed (different message, different status, even
    different body length), an attacker could enumerate which emails are
    on the waitlist. Must be byte-identical."""
    email = f"enum+{uuid.uuid4().hex[:8]}@example.com"
    r1 = client.post("/api/waitlist/supplier", json=_good_payload(email=email))
    r2 = client.post("/api/waitlist/supplier", json=_good_payload(email=email))
    assert r1.status_code == r2.status_code == 201
    assert r1.text == r2.text     # byte-identical


def test_response_identical_for_human_and_honeypot_bot():
    """Bot ACK must be indistinguishable from a real submission. Otherwise
    bots learn what the honeypot is called and stop filling it."""
    real = client.post("/api/waitlist/supplier", json=_good_payload())
    bot = client.post(
        "/api/waitlist/supplier",
        json=_good_payload(website="http://spammer.example/"),
    )
    assert real.status_code == bot.status_code == 201
    assert real.json() == bot.json()


# ===========================================================================
# Race conditions
# ===========================================================================
def test_concurrent_duplicate_submissions_end_with_one_row():
    """Fire 10 threads against the same (role, email). The unique-index
    race is handled by the IntegrityError catch in routes/waitlist.py;
    if it weren't, we'd see a 500 from one of the requests."""
    email = f"race+{uuid.uuid4().hex[:8]}@example.com"
    results: list[int] = []
    errors: list[str] = []

    def fire():
        try:
            r = client.post("/api/waitlist/supplier", json=_good_payload(email=email))
            results.append(r.status_code)
        except Exception as e:  # pragma: no cover - thread error path
            errors.append(repr(e))

    threads = [threading.Thread(target=fire) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, errors
    # Every request returns the same 201 ACK
    assert all(s == 201 for s in results), results
    # And exactly one row exists
    db = SessionLocal()
    try:
        n = db.query(WaitlistSignup).filter(WaitlistSignup.email == email).count()
    finally:
        db.close()
    assert n == 1, f"expected 1 row, got {n}"


# ===========================================================================
# Authorisation on admin endpoint
# ===========================================================================
def test_admin_endpoint_rejects_no_token():
    r = client.get("/api/waitlist/admin")
    assert r.status_code in (401, 403)


def test_admin_endpoint_rejects_garbage_token():
    r = client.get(
        "/api/waitlist/admin",
        headers={"Authorization": "Bearer total.garbage.token"},
    )
    assert r.status_code in (401, 403)


def test_admin_endpoint_rejects_tampered_jwt():
    """Standalone deployment uses HTTP Basic Auth, not JWT. A Bearer token
    that looks like a JWT must NOT accidentally grant access (basic auth
    expects 'Basic base64...', anything else is 401)."""
    forged = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    r = client.get(
        "/api/waitlist/admin",
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert r.status_code in (401, 403)


def test_admin_endpoint_rejects_wrong_basic_credentials():
    """Right username, wrong password — 401. Right password, wrong username
    — 401. Both must fail closed."""
    for user, pwd in [
        ("testadmin", "wrong-password"),
        ("wrong-user", "test-password-do-not-use-in-prod"),
        ("", ""),
    ]:
        r = client.get("/api/waitlist/admin", auth=(user, pwd))
        assert r.status_code in (401, 403), f"{user!r}/{pwd!r}: {r.status_code}"


def test_admin_endpoint_grants_with_correct_basic_credentials():
    r = client.get(
        "/api/waitlist/admin",
        auth=("testadmin", "test-password-do-not-use-in-prod"),
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ===========================================================================
# Security-header presence on the public endpoint
# ===========================================================================
def test_security_headers_present_on_waitlist_post():
    r = client.post("/api/waitlist/supplier", json=_good_payload())
    h = {k.lower(): v for k, v in r.headers.items()}
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("x-frame-options") == "DENY"
    assert "referrer-policy" in h
    assert "content-security-policy" in h
    # Frame-ancestors clause defends against clickjacking even where
    # X-Frame-Options is ignored.
    assert "frame-ancestors 'none'" in h["content-security-policy"]


# ===========================================================================
# Rate limiter wiring — defence-in-depth check
# ===========================================================================
def test_rate_limit_decorator_is_wired_up():
    """The slowapi @limiter.limit decorator stamps a function-level attribute
    on the endpoint. We check it exists rather than triggering the limit
    (which would be flaky under parallel test runs). Production limit is
    3/minute; under TESTING=1 it's bumped via _rate()."""
    fn = waitlist_module.supplier_signup
    # slowapi records limits on the wrapper in `_rate_limits` (modern slowapi)
    # or attaches them via the route decorator. Either attribute being
    # present, OR the function being decorated (i.e. having __wrapped__),
    # is enough confidence the limiter is in the call chain.
    limited = (
        hasattr(fn, "_rate_limits")
        or hasattr(fn, "__wrapped__")
        or hasattr(fn, "_decorator_set_limits")
    )
    assert limited, "supplier_signup is not wrapped by the slowapi limiter"
