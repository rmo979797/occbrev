"""Transactional email for the waitlist.

Sends a single confirmation email after a successful supplier signup via
Resend (https://resend.com). The send is fired by the route as a FastAPI
BackgroundTask so a Resend outage / slow response never blocks the form
submission. Failures are logged but never raised — the user already saw
the celebration screen by the time this runs.

Security posture:
* No user input is interpolated into the HTML without escaping — the
  business name and email address go through `html.escape` before they
  hit the template.
* Resend API key is read from env at send time so a rotated key takes
  effect on the next dispatch without a restart.
* In dev / tests (no RESEND_API_KEY), the sender logs to stdout instead
  of dispatching. Tests stay hermetic and developers can run the form
  without external creds.

Banner image:
* If `EMAIL_BANNER_URL` is set, the template uses it as a full-bleed
  hero `<img>` at the top.
* If unset (current default until the user uploads a banner), the
  template renders a CSS-only branded header with the gold wordmark
  on a dark gradient — looks good in every major email client.
"""
from __future__ import annotations

import html
import logging
from typing import Optional

from config import settings

logger = logging.getLogger("occasions.email")

# Brand palette mirrored from the landing page. Kept in this file so the
# email design has no runtime dependency on the frontend CSS.
_GOLD_LIGHT = "#F5E6B8"
_GOLD       = "#D4A843"
_GOLD_DARK  = "#B8892F"
_BG_DARK    = "#0E0E1A"
_BG_BLACK   = "#0D0D17"
_TEXT       = "#FFFFFF"
_TEXT_MUTED = "rgba(255,255,255,0.72)"


def _enabled() -> bool:
    return bool(settings.RESEND_API_KEY)


def send_waitlist_confirmation(
    *,
    to_email: str,
    business_name: str,
    category_label: Optional[str] = None,
    secondary_category_labels: Optional[list[str]] = None,
) -> bool:
    """Send the supplier confirmation email. Returns True on success or
    when running in dev-log mode; False on any send failure. Never raises."""
    subject = "You're on the Occasions founding-supplier list"

    html_body = _render_html(
        business_name=business_name,
        category_label=category_label,
        secondary_category_labels=secondary_category_labels,
    )
    text_body = _render_text(
        business_name=business_name,
        category_label=category_label,
        secondary_category_labels=secondary_category_labels,
    )

    if not _enabled():
        # Dev / test mode — log the email so developers know it would have gone.
        logger.warning(
            "[email:dev] would send to=%s subject=%s\n--- text ---\n%s",
            to_email, subject, text_body,
        )
        return True

    return _dispatch(
        to_email=to_email, subject=subject, html_body=html_body, text_body=text_body,
    )


def _dispatch(
    *,
    to_email: str,
    subject: str,
    html_body: Optional[str],
    text_body: str,
) -> bool:
    """Low-level Resend send. Lazy-imports the SDK and catches every error
    so callers always get a bool, never an exception."""
    # Lazy import so test environments without `resend` installed still load.
    try:
        import resend  # type: ignore
    except ImportError:
        logger.error("resend package not installed; cannot send email to %s", to_email)
        return False

    resend.api_key = settings.RESEND_API_KEY
    sender = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
    params = {
        "from": sender,
        "to": [to_email],
        "subject": subject,
        "text": text_body,
    }
    if html_body:
        params["html"] = html_body
    if settings.EMAIL_REPLY_TO:
        params["reply_to"] = settings.EMAIL_REPLY_TO

    try:
        result = resend.Emails.send(params)
        logger.info("Resend accepted id=%s to=%s", result.get("id"), to_email)
        return True
    except Exception as exc:  # noqa: BLE001 — third-party SDK exceptions vary
        logger.exception("Email send to %s failed: %s", to_email, exc)
        return False


def send_admin_signup_notification(
    *,
    business_name: str,
    email: str,
    category: str,
    category_other: Optional[str],
    secondary_categories: Optional[list[str]] = None,
    service_area: str,
    instagram_handle: Optional[str],
    feedback: Optional[str],
    ready_to_onboard: bool,
    ip: Optional[str],
) -> bool:
    """Send a plain-text internal receipt to the operator when a new
    supplier signs up. Address is read from settings.ADMIN_NOTIFICATION_EMAIL;
    if that's empty the call is a no-op (returns True so the caller doesn't
    panic). Never raises.

    Plain-text only — no banner, no styling — because this is for you, not
    a marketing surface, and plain-text emails always render correctly,
    never trip spam filters, and quote cleanly when forwarded.
    """
    to_email = settings.ADMIN_NOTIFICATION_EMAIL
    if not to_email:
        return True  # feature disabled — silent no-op

    # Compact subject line so a glance at the inbox tells you who joined.
    subject = f"[Waitlist] New supplier: {business_name}"

    category_display = category
    if category == "other" and category_other:
        category_display = f"other ({category_other})"
    if secondary_categories:
        category_display = (
            f"{category_display}  +  also: {', '.join(secondary_categories)}"
        )

    lines = [
        "New supplier joined the Occasions waitlist.",
        "",
        f"Business:    {business_name}",
        f"Email:       {email}",
        f"Category:    {category_display}",
        f"Area:        {service_area}",
        f"Instagram:   {('@' + instagram_handle) if instagram_handle else '-'}",
        f"Ready in 2w: {'yes' if ready_to_onboard else 'no'}",
        f"IP:          {ip or '-'}",
        "",
        "What they told us:",
        f"  {feedback}" if feedback else "  (no answer)",
        "",
        "---",
        "Admin: https://occasions.london/api/waitlist/admin",
        "(Replies to this email go to your own inbox, not the supplier.)",
    ]
    text_body = "\n".join(lines)

    if not _enabled():
        logger.warning(
            "[email:dev] would notify admin to=%s subject=%s\n--- text ---\n%s",
            to_email, subject, text_body,
        )
        return True

    return _dispatch(
        to_email=to_email, subject=subject, html_body=None, text_body=text_body,
    )


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
def _join_natural(items: list[str]) -> str:
    """Render a list as a human sentence fragment: ``a`` / ``a and b`` /
    ``a, b and c``. Used for the category sentence so an email reads like
    a person wrote it, not a switch statement."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _category_sentence(
    primary: Optional[str],
    secondaries: Optional[list[str]],
) -> Optional[str]:
    """Build the 'We've noted you down…' sentence based on how many
    categories the supplier picked.

    * 0 (no primary): None — caller should skip the line entirely.
    * 1 primary:           "We've noted you down as a <primary>."
    * 1 primary + 1+:      "We've noted you down across <primary>, <s1> and <s2>."

    'Across' (not 'as a') in the multi-cat case avoids the awkward
    article mismatch ("as a florist, decorator and dessert stylist" reads
    fine in speech but adds a beat the eye trips on; 'across' makes the
    structure self-explanatory).
    """
    if not primary:
        return None
    extras = [s for s in (secondaries or []) if s]
    if not extras:
        return f"We've noted you down as a {primary}."
    all_labels = [primary, *extras]
    return f"We've noted you down across {_join_natural(all_labels)}."


def _render_text(
    *,
    business_name: str,
    category_label: Optional[str],
    secondary_category_labels: Optional[list[str]] = None,
) -> str:
    """Plain-text version. Required for deliverability — spam filters
    penalise HTML-only emails. Kept short and human."""
    safe_name = business_name.strip() or "there"
    lines = [
        f"Hi {safe_name},",
        "",
        "Thanks for joining the Occasions founding-supplier waitlist.",
    ]
    sentence = _category_sentence(category_label, secondary_category_labels)
    if sentence:
        lines.append(sentence)
    lines += [
        "",
        "Here's what happens next:",
        "",
        "  1. We hand-review every supplier — usually within a few days.",
        "  2. If you're a fit, we'll email you to confirm.",
        "  3. Closer to launch (Summer 2027) we'll invite you to set up",
        "     your full profile so everything is polished on day one.",
        "",
        "Questions in the meantime? Reply to this email — it goes straight",
        "to us, not a help desk.",
        "",
        "Occasions",
        "London's marketplace for themed event suppliers",
        "https://occasions.london",
        "",
        "If you didn't sign up, ignore this email and we'll delete your row.",
        "Privacy notice: https://occasions.london (footer link)",
    ]
    return "\n".join(lines)


def _render_html(
    *,
    business_name: str,
    category_label: Optional[str],
    secondary_category_labels: Optional[list[str]] = None,
) -> str:
    """HTML email. Inline styles only — most email clients strip <style>
    blocks. Table-based layout for the broadest client support
    (Gmail, Outlook desktop, Apple Mail, Yahoo, Proton)."""
    safe_name = html.escape(business_name.strip() or "there")
    safe_primary = html.escape(category_label) if category_label else None
    safe_secondaries = [
        html.escape(s) for s in (secondary_category_labels or []) if s
    ]

    # Header — either the supplier-uploaded logo (if EMAIL_BANNER_URL is
    # set) or a CSS-only branded block. The CSS-only fallback is good-
    # looking enough to ship immediately; the image upgrade is a one-line
    # env-var change.
    #
    # When the env var is set, we treat the asset as a logo (not a full-
    # bleed banner) — centred, max ~260px wide, sitting on the same dark
    # gradient as the fallback so the rest of the email blends seamlessly.
    # The "Founding Supplier" eyebrow stays above it for context regardless
    # of which header variant renders.
    if settings.EMAIL_BANNER_URL:
        safe_banner = html.escape(settings.EMAIL_BANNER_URL, quote=True)
        header = f"""
        <tr><td style="background:linear-gradient(135deg,{_BG_BLACK} 0%,{_BG_DARK} 100%);padding:36px 32px 24px 32px;text-align:center;">
          <div style="font-size:14px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:{_GOLD};margin-bottom:18px;">
            &middot; Founding Supplier &middot;
          </div>
          <img src="{safe_banner}"
               alt="Occasions London"
               width="240"
               style="display:inline-block;width:240px;max-width:60%;height:auto;border:0;outline:none;text-decoration:none;" />
        </td></tr>
        """.strip()
    else:
        header = f"""
        <tr><td style="background:linear-gradient(135deg,{_BG_BLACK} 0%,{_BG_DARK} 100%);padding:48px 32px 40px 32px;text-align:center;">
          <div style="font-size:14px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:{_GOLD};margin-bottom:12px;">
            &middot; Founding Supplier &middot;
          </div>
          <div style="font-family:Georgia,'Times New Roman',serif;font-size:44px;font-weight:700;letter-spacing:-0.02em;line-height:1;color:{_GOLD_LIGHT};">
            Occasions
          </div>
        </td></tr>
        """.strip()

    # Category sentence — single or multi. Each label gets the gold
    # accent so multi-category suppliers see all their categories
    # highlighted, not just the primary.
    if safe_primary:
        gold = _GOLD_LIGHT
        primary_html = f'<strong style="color:{gold};">{safe_primary}</strong>'
        if not safe_secondaries:
            sentence_html = f"We've noted you down as a {primary_html}."
        else:
            highlighted = [primary_html] + [
                f'<strong style="color:{gold};">{s}</strong>'
                for s in safe_secondaries
            ]
            sentence_html = (
                f"We've noted you down across {_join_natural(highlighted)}."
            )
        category_line = (
            f'<p style="margin:0 0 18px 0;font-size:15px;color:{_TEXT_MUTED};">'
            f"{sentence_html}"
            "</p>"
        )
    else:
        category_line = ""

    body = f"""
    <tr><td style="background:{_BG_DARK};padding:40px 36px 32px 36px;color:{_TEXT};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <h1 style="margin:0 0 16px 0;font-size:24px;font-weight:700;letter-spacing:-0.01em;color:{_TEXT};">
        Hi {safe_name},
      </h1>
      <p style="margin:0 0 18px 0;font-size:16px;line-height:1.55;color:{_TEXT_MUTED};">
        Thanks for joining the <strong style="color:{_GOLD_LIGHT};">founding-supplier waitlist</strong>.
        We're hand-building Occasions to launch in London in Summer 2027 &mdash; and you're now in the queue.
      </p>
      {category_line}

      <div style="margin:28px 0 8px 0;padding:24px 24px 20px 24px;background:rgba(255,255,255,0.04);border:1px solid rgba(212,168,67,0.18);border-radius:14px;">
        <div style="font-size:13px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:{_GOLD};margin-bottom:14px;">
          What happens next
        </div>
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr>
            <td valign="top" style="width:28px;color:{_GOLD};font-size:15px;font-weight:700;padding:2px 0 14px 0;">1</td>
            <td style="font-size:15px;line-height:1.55;color:{_TEXT_MUTED};padding-bottom:14px;">
              We <strong style="color:{_TEXT};">hand-review</strong> every supplier &mdash; usually within a few days.
            </td>
          </tr>
          <tr>
            <td valign="top" style="width:28px;color:{_GOLD};font-size:15px;font-weight:700;padding:2px 0 14px 0;">2</td>
            <td style="font-size:15px;line-height:1.55;color:{_TEXT_MUTED};padding-bottom:14px;">
              If you're a fit, we'll <strong style="color:{_TEXT};">email you to confirm</strong>.
            </td>
          </tr>
          <tr>
            <td valign="top" style="width:28px;color:{_GOLD};font-size:15px;font-weight:700;padding:2px 0 0 0;">3</td>
            <td style="font-size:15px;line-height:1.55;color:{_TEXT_MUTED};">
              Closer to launch we'll invite you to <strong style="color:{_TEXT};">set up your full profile</strong> so everything is polished on day one.
            </td>
          </tr>
        </table>
      </div>

      <p style="margin:24px 0 0 0;font-size:15px;line-height:1.55;color:{_TEXT_MUTED};">
        Questions in the meantime? Just reply to this email &mdash; it goes straight to us.
      </p>
      <p style="margin:24px 0 0 0;font-size:15px;line-height:1.55;color:{_TEXT_MUTED};">
        See you soon,<br>
        <strong style="color:{_GOLD_LIGHT};">The Occasions team</strong>
      </p>
    </td></tr>
    """.strip()

    footer = f"""
    <tr><td style="background:{_BG_BLACK};padding:24px 36px 28px 36px;border-top:1px solid rgba(255,255,255,0.06);text-align:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <div style="font-size:12px;color:rgba(255,255,255,0.5);line-height:1.6;">
        Occasions &middot; London's marketplace for themed event suppliers<br>
        <a href="https://occasions.london" style="color:{_GOLD};text-decoration:none;">occasions.london</a>
        &nbsp;&middot;&nbsp;
        <a href="mailto:privacy@occasions.london" style="color:rgba(255,255,255,0.5);text-decoration:underline;">Privacy &amp; data removal</a>
      </div>
      <div style="font-size:11px;color:rgba(255,255,255,0.32);margin-top:14px;line-height:1.55;">
        If you didn't sign up, ignore this email and we'll delete your row. To be removed sooner, email
        <a href="mailto:privacy@occasions.london" style="color:rgba(255,255,255,0.5);">privacy@occasions.london</a>.
      </div>
    </td></tr>
    """.strip()

    # Outer wrapper — light grey body so the dark card sits on a real
    # surface in most clients. Gmail / Outlook handle this well.
    return f"""<!doctype html>
<html lang="en-GB">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome to Occasions</title>
</head>
<body style="margin:0;padding:0;background:#F2F2F4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <!-- Preheader: shows in the inbox preview, hidden in the body -->
  <div style="display:none!important;max-height:0;overflow:hidden;opacity:0;color:transparent;visibility:hidden;mso-hide:all;">
    You're on the Occasions founding-supplier list. Here's what happens next.
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F2F2F4;padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;background:{_BG_DARK};border-radius:18px;overflow:hidden;box-shadow:0 8px 40px rgba(0,0,0,0.15);">
        {header}
        {body}
        {footer}
      </table>
    </td></tr>
  </table>
</body>
</html>"""
