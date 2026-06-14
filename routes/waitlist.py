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

import os
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import require_admin
from database import get_db
from models import WaitlistSignup


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
# Keep these in sync with the labels rendered on the landing page.
# ---------------------------------------------------------------------------
SUPPLIER_CATEGORIES = {
    "caterer", "decorator", "photographer", "cake", "florist",
    "dj", "entertainer", "venue", "balloon", "other",
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
# Schemas
# ---------------------------------------------------------------------------
class SupplierWaitlistIn(BaseModel):
    business_name: str = Field(min_length=2, max_length=80)
    category: str = Field(min_length=2, max_length=30)
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

    @field_validator("business_name", "feedback")
    @classmethod
    def _trim(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v


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
    db: Session = Depends(get_db),
):
    if _is_bot_submission(data):
        # Bot — ACK politely, write nothing.
        return _ack()

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
        service_area=data.service_area,
        instagram_handle=data.instagram_handle,
        feedback=data.feedback,
        ready_to_onboard=data.ready_to_onboard,
        ip=_client_ip(request),
        user_agent=(request.headers.get("user-agent", "") or "")[:500],
    )
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
