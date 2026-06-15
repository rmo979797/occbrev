"""Waitlist endpoints — pre-launch supplier signup.

Two endpoints:

* ``POST /api/waitlist/supplier`` — supplier waitlist signup (public)
* ``GET  /api/waitlist/admin``    — admin-only list/export

Supplier-only by design: at this stage the bottleneck is supply, not
demand. The underlying ``WaitlistSignup`` model keeps a ``role`` column
so a customer list can be bolted on later without a migration.

Security posture (unauthenticated, internet-facing form):

* Rate limited at 3/min per IP (bumped to 10000/min under ``TESTING=1``).
* Honeypot field ``website`` — invisible to humans, bots fill it; non-empty
  submissions are silently accepted (201 OK) but never written. We don't
  return an error because we don't want bots to learn the field name.
* Submission timing check — anything completed in under 1.5 seconds is
  treated as bot and silently dropped. ``form_loaded_at`` is set by the
  page on render.
* Pydantic-driven length caps on every string field (no DB bloat).
* Strict email format check + lowercase normalisation.
* Instagram handle stripped to ``[A-Za-z0-9._]+`` (max 30 chars) and
  ``@`` prefix is dropped. Anything fancier is rejected, not sanitised.
* Category / service_area validated against fixed allow-lists.
* Idempotent: re-submission with the same (role, email) updates the
  existing row, no duplicate keys, no info leak about whether the email
  was already on the list (always returns the same 201 message).
* IP + UA captured (moderation only, never displayed).
* No HTML, JS, or template rendering — pure JSON in, JSON out.
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import require_admin
from database import get_db
from email_sender import send_waitlist_confirmation
from models import WaitlistSignup


logger = logging.getLogger("occasions.waitlist")
router = APIRouter(prefix="/api/waitlist", tags=["Waitlist"])


# ---------------------------------------------------------------------------
# Rate limiting (slowapi)
# ---------------------------------------------------------------------------
_TESTING = os.environ.get("TESTING") == "1"
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000/minute"] if _TESTING else [],
)


def _rate(spec: str) -> str:
    return "10000/minute" if _TESTING else spec


# ---------------------------------------------------------------------------
# Allow-lists. Anything not in these lists is rejected, NOT silently coerced.
# Keep these in sync with the labels rendered on the landing page AND with
# enums.SupplierCategory in the main marketplace app — the slugs are the
# kebab-case forms of the canonical labels.
# ---------------------------------------------------------------------------
SUPPLIER_CATEGORIES = {
    "backdrop-prop-hire",
    "balloon-artist",
    "cake-maker",
    "candy-cart",
    "caterer",
    "decorator",
    "dessert-stylist",
    "face-painter",
    "florist",
    "linen-hire",
    "neon-sign-hire",
    "party-favours",
    "photographer",
    "other",
}

# Human-readable label for each category slug. Used in the confirmation
# email ("We've noted you down as a balloon artist"). Kept beside the
# allow-list so a new slug forces us to add a label too.
CATEGORY_LABELS = {
    "backdrop-prop-hire": "backdrop & prop hire supplier",
    "balloon-artist": "balloon artist",
    "cake-maker": "cake maker",
    "candy-cart": "candy cart supplier",
    "caterer": "caterer",
    "decorator": "decorator",
    "dessert-stylist": "dessert stylist",
    "face-painter": "face painter",
    "florist": "florist",
    "linen-hire": "linen hire supplier",
    "neon-sign-hire": "neon sign hire supplier",
    "party-favours": "party favours supplier",
    "photographer": "photographer",
    "other": "supplier",
}
SERVICE_AREAS = {
    "central-london", "north-london", "south-london",
    "east-london", "west-london", "outside-london",
}

# Minimum seconds between form-render and submit. Bots submit instantly;
# real humans take at least a few seconds to fill the form.
MIN_SUBMIT_SECONDS = 1.5

# Instagram handles: alnum + . + _, length 1-30. Strict, not sanitised.
INSTAGRAM_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

# ---------------------------------------------------------------------------
# Anti-abuse — defends the Resend reputation and the admin queue.
#
# Threat model (what these defend against):
#  * Email-bombing relay: attacker submits N victim addresses → each victim
#    gets a confirmation email "from us". Damages deliverability and looks
#    like spam — Resend can suspend us if reports spike. PER_IP_DAILY cap
#    is the primary control.
#  * Disposable-email churn: bulk junk via mailinator/guerrillamail etc.
#  * Impersonation: bad actor submits a real competitor's Instagram handle
#    paired with their own email so the admin queue shows misleading rows.
#
# Posture: every defence below results in a silent 201 ACK with NO DB write
# and NO confirmation email. The attacker can't tell which check fired —
# same response as a real signup. Real abuse attempts are logged loudly so
# we can review IP / handle patterns in the Railway / Sentry logs.
# ---------------------------------------------------------------------------
# Max distinct emails a single IP may register in 24h. Re-submissions of
# an email already attached to that IP don't count (they're updates).
# Tuned for: a single office network occasionally signing up a handful of
# colleagues = fine. A bot spraying thousands of victim emails = blocked.
# Bumped to a huge number under TESTING=1 so the shared 127.0.0.1 IP
# across the test suite doesn't trip the cap. Individual tests that want
# to exercise the limit monkeypatch this constant down.
PER_IP_DAILY_NEW_EMAILS = 100_000 if _TESTING else 5

# Disposable-email domain blocklist. Kept short and obvious — exhaustive
# lists exist but go stale; this catches the lazy 80%. Add to it from
# admin-log review as new patterns appear.
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "10minutemail.com", "10minutemail.net", "tempmail.com", "temp-mail.org",
    "throwaway.email", "trashmail.com", "yopmail.com", "fakeinbox.com",
    "getnada.com", "sharklasers.com", "maildrop.cc", "mintemail.com",
    "dispostable.com", "mailcatch.com", "spamgourmet.com", "tempinbox.com",
    "mvrht.net", "discard.email", "33mail.com", "anonbox.net",
}


def _is_disposable_email(email: str) -> bool:
    """True if email's domain is on the disposable blocklist. Case-insensitive."""
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower().strip()
    return domain in DISPOSABLE_EMAIL_DOMAINS


def _ip_exceeded_daily_quota(db: Session, ip: Optional[str], role: str) -> bool:
    """True if this IP has already created ``PER_IP_DAILY_NEW_EMAILS`` distinct
    emails for this role in the last 24h. Re-submissions don't count because
    they don't create new rows.

    Missing IP (rare — only if Request.client is None AND no XFF) is never
    blocked; we err on the side of letting real humans through and lean on
    the other defences (honeypot, timing, slowapi).
    """
    if not ip:
        return False
    cutoff = datetime.utcnow() - timedelta(hours=24)
    distinct = (
        db.query(WaitlistSignup.email)
        .filter(WaitlistSignup.role == role)
        .filter(WaitlistSignup.ip == ip)
        .filter(WaitlistSignup.created_at >= cutoff)
        .distinct()
        .count()
    )
    return distinct >= PER_IP_DAILY_NEW_EMAILS


def _handle_taken_by_different_email(
    db: Session, role: str, handle: Optional[str], email: str
) -> bool:
    """True if this Instagram handle is already registered to a DIFFERENT
    email. Lets the legit "same person updates their submission" path
    through (same email + same handle) while blocking impersonation
    attempts (different email submitting an existing handle)."""
    if not handle:
        return False
    return (
        db.query(WaitlistSignup.id)
        .filter(WaitlistSignup.role == role)
        .filter(WaitlistSignup.instagram_handle == handle)
        .filter(WaitlistSignup.email != email)
        .first()
        is not None
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class SupplierWaitlistIn(BaseModel):
    business_name: str = Field(min_length=2, max_length=80)
    category: str = Field(min_length=2, max_length=30)
    # Free-text label captured when the user picks "other". Lets us learn
    # which categories to add next. Kept short — it's a label, not prose.
    # Silently nulled when category != "other" so a tampered payload can't
    # smuggle freeform text into validated rows.
    category_other: Optional[str] = Field(default=None, max_length=60)
    service_area: str = Field(min_length=2, max_length=30)
    instagram_handle: Optional[str] = Field(default=None, max_length=40)
    feedback: Optional[str] = Field(default=None, max_length=300)
    ready_to_onboard: bool = False
    email: EmailStr
    # Honeypot — must be empty. Bots fill every field by default.
    website: Optional[str] = Field(default="", max_length=200)
    # Page sets this to Date.now()/1000 on render. We compare against
    # server clock; submissions inside MIN_SUBMIT_SECONDS are dropped.
    form_loaded_at: Optional[float] = None

    @field_validator("email")
    @classmethod
    def _email_lowercase(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("category")
    @classmethod
    def _check_category(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in SUPPLIER_CATEGORIES:
            raise ValueError("invalid category")
        return v

    @field_validator("service_area")
    @classmethod
    def _check_area(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in SERVICE_AREAS:
            raise ValueError("invalid service area")
        return v

    @field_validator("instagram_handle")
    @classmethod
    def _clean_instagram(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().lstrip("@")
        if not v:
            return None
        if not INSTAGRAM_RE.match(v):
            raise ValueError("invalid instagram handle")
        return v

    @field_validator("business_name", "feedback", "category_other")
    @classmethod
    def _trim(cls, v: Optional[str]) -> Optional[str]:
        if not isinstance(v, str):
            return v
        v = v.strip()
        return v or None

    @model_validator(mode="after")
    def _other_only_with_other(self) -> "SupplierWaitlistIn":
        # If the user didn't pick "other", drop any free-text label — stops
        # a tampered payload smuggling content past the category allow-list.
        if self.category != "other":
            self.category_other = None
        return self


class WaitlistOut(BaseModel):
    success: bool
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _client_ip(request: Request) -> Optional[str]:
    """Prefer X-Forwarded-For (Railway sets this), fall back to peer."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client else None


def _is_bot_submission(data: SupplierWaitlistIn) -> bool:
    """Return True if the submission looks like a bot. Caller should ACK
    with a normal 201 message but NOT write to the DB."""
    # 1. Honeypot — humans never see this field, bots fill it
    if data.website:
        return True
    # 2. Timing — too-fast submission is a bot. We allow missing
    #    form_loaded_at (older browsers / JS-disabled fall back) so we
    #    don't punish edge cases, but if present it must be old enough.
    if data.form_loaded_at:
        try:
            elapsed = time.time() - float(data.form_loaded_at)
        except (TypeError, ValueError):
            return True
        if elapsed < MIN_SUBMIT_SECONDS:
            return True
        # Also reject submissions claiming to be from the future — clock-
        # skew or a tampered field. Treat as bot.
        if elapsed < 0:
            return True
    return False


def _ack() -> WaitlistOut:
    """Generic success response. Used for both real signups and silent
    bot drops, so no info-leak about which submissions were rejected."""
    return WaitlistOut(success=True, message="You're on the list — we'll be in touch soon.")


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
@router.post("/supplier", response_model=WaitlistOut, status_code=201)
@limiter.limit(_rate("3/minute"))
def supplier_signup(
    request: Request,
    data: SupplierWaitlistIn,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if _is_bot_submission(data):
        # Bot — ACK politely, write nothing.
        return _ack()

    client_ip = _client_ip(request)

    # --- Anti-abuse layer (silent ACK + log on each hit) --------------------
    # Defends Resend reputation and the admin queue. Every rejection looks
    # IDENTICAL to a real success to the caller — no info leak about which
    # check fired or which thresholds exist.
    if _is_disposable_email(data.email):
        logger.warning(
            "waitlist: disposable email blocked ip=%s email=%s",
            client_ip, data.email,
        )
        return _ack()

    if _ip_exceeded_daily_quota(db, client_ip, "supplier"):
        logger.warning(
            "waitlist: per-IP daily quota exceeded ip=%s attempted_email=%s",
            client_ip, data.email,
        )
        return _ack()

    if _handle_taken_by_different_email(
        db, "supplier", data.instagram_handle, data.email
    ):
        logger.warning(
            "waitlist: instagram handle collision (possible impersonation) "
            "ip=%s handle=%s attempted_email=%s",
            client_ip, data.instagram_handle, data.email,
        )
        return _ack()
    # -----------------------------------------------------------------------

    # Idempotent upsert. We don't want to leak whether the email was
    # already on the list (timing/error responses tell attackers things).
    existing = (
        db.query(WaitlistSignup)
        .filter(WaitlistSignup.role == "supplier")
        .filter(WaitlistSignup.email == data.email)
        .first()
    )
    fields = dict(
        business_name=data.business_name,
        category=data.category,
        category_other=data.category_other,
        service_area=data.service_area,
        instagram_handle=data.instagram_handle,
        feedback=data.feedback,
        ready_to_onboard=data.ready_to_onboard,
        ip=client_ip,
        user_agent=(request.headers.get("user-agent", "") or "")[:500],
    )
    is_new = existing is None
    if existing:
        for k, v in fields.items():
            setattr(existing, k, v)
    else:
        db.add(WaitlistSignup(role="supplier", email=data.email, **fields))
    try:
        db.commit()
    except IntegrityError:
        # Race against the uq_waitlist_role_email index — another request
        # for the same email landed first. Same ACK, no leak.
        db.rollback()
        is_new = False  # don't re-send confirmation on race

    # Fire the confirmation email out-of-band. Only for first-time signups
    # so re-submissions don't spam the user. Background task means a slow
    # Resend response never blocks the form — the user already saw the
    # celebration screen.
    if is_new:
        label = CATEGORY_LABELS.get(data.category, "supplier")
        # When category == "other" with custom text, use the user's wording
        # instead of the generic "supplier" label.
        if data.category == "other" and data.category_other:
            label = data.category_other
        background.add_task(
            send_waitlist_confirmation,
            to_email=data.email,
            business_name=data.business_name,
            category_label=label,
        )
    return _ack()


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@router.get("/admin")
def admin_list_waitlist(
    role: Optional[str] = None,
    db: Session = Depends(get_db),
    admin: str = Depends(require_admin),
):
    """Admin-only list of waitlist signups, optionally filtered by role."""
    q = db.query(WaitlistSignup)
    if role in {"supplier", "customer"}:
        q = q.filter(WaitlistSignup.role == role)
    return q.order_by(WaitlistSignup.created_at.desc()).all()
