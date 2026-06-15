# Occasions Waitlist

Pre-launch supplier waitlist for [occasions.london](https://occasions.london).
Deliberately isolated from the main marketplace — single table, no user
accounts, no payments. If this box is compromised, the blast radius is the
waitlist signups and nothing else.

## Stack

- FastAPI + SQLAlchemy 2 + Alembic
- Postgres in prod (SQLite locally for tests)
- Vanilla-JS frontend (no build step)
- Slowapi for rate limiting, HTTP Basic Auth for the admin endpoint

## Local development

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # then edit ADMIN_PASS at minimum
alembic upgrade head
uvicorn main:app --reload --port 8080
```

Open <http://127.0.0.1:8080> to see the landing page.

Run the tests:

```bash
TESTING=1 pytest -q
```

## Deployment (Railway)

1. Push this repo to GitHub.
2. New Railway project → "Deploy from GitHub" → pick this repo.
3. Add the Postgres plugin (one click). `DATABASE_URL` is injected automatically.
4. Set these env vars in Railway → **Variables**:
   - `ENVIRONMENT=production`
   - `ADMIN_USER` = your choice
   - `ADMIN_PASS` = a long random string (`python -c "import secrets;print(secrets.token_urlsafe(48))"`)
   - `RESEND_API_KEY` = `re_...` (from <https://resend.com> after verifying the domain)
   - `EMAIL_FROM` = `hello@occasions.london` *(optional, this is the default)*
   - `EMAIL_BANNER_URL` = public URL of a 1200x300 PNG/JPG hero *(optional; falls back to a CSS-only branded header when unset)*
   - `ADMIN_NOTIFICATION_EMAIL` = inbox to receive a plain-text receipt on every new signup *(optional; leave empty to disable)*
   - `SENTRY_DSN` *(optional)*
5. Deploy. Railway gives you a `*.up.railway.app` URL — verify the form works.
6. In Cloudflare DNS, add a `CNAME @ → your-app.up.railway.app` (proxy on).
7. In Railway → Settings → Domains, add `occasions.london`. HTTPS is automatic.

`alembic upgrade head` runs on every deploy via the `Procfile` and
`railway.json` startup command, so schema changes are applied before the
new build accepts traffic.

## Admin export

```bash
curl -u admin:YOUR_ADMIN_PASS https://occasions.london/api/waitlist/admin
```

Returns JSON of every signup. Pipe through `jq` for a quick CSV.

## Security posture (summary)

- Slowapi rate limit: 3/min per IP on the public endpoint
- Per-IP daily cap on distinct new emails (5/24h in prod) — stops email-bombing
- Disposable-email domain blocklist (mailinator, guerrillamail, etc.)
- Instagram-handle impersonation guard (same handle + different email = silent drop)
- Honeypot field + submission timing check (sub-1.5s = bot, silently dropped)
- Every anti-abuse defence returns a byte-identical 201 ACK — no enumeration
- Pydantic length caps + allow-listed enums on every field
- Idempotent upsert: same email + role only ever creates one row
- CSP, HSTS, X-Frame-Options=DENY, no inline JS
- Admin endpoint behind HTTP Basic Auth (constant-time compare)
- App refuses to boot in production with default admin credentials
- Confirmation + admin emails fire via FastAPI BackgroundTasks; a Resend
  outage logs an error but never blocks the form submission

Full test coverage in [tests/](tests/) (125+ assertions across SQLi, XSS,
CRLF, mass-assignment, type confusion, race conditions, auth bypass
attempts, resource exhaustion, anti-abuse defences, and email flows).

## Roadmap (parked for later)

Things the codebase is ready for but the operator hasn't done yet:

- **Hero image for the confirmation email.** Design a 1200x300 PNG/JPG,
  upload to any public URL, set `EMAIL_BANNER_URL` env var. Until then the
  email renders a CSS-only branded gold-on-dark header — polished but
  generic.
- **Sentry error monitoring.** Sign up at <https://sentry.io>, create a
  Python project, paste the DSN into the `SENTRY_DSN` env var. Already
  wired — no code change needed.
- **Postgres backups in Railway.** Railway → Postgres plugin → Backups
  tab → enable daily snapshots. Free on the hobby tier.
- **Trade mark filing** for the brand name. UK IPO (~£170-270 depending
  on class count) — ideally 3-6 months before public launch.
- **Limited company formation.** Companies House registration (£50,
  10 minutes online) — before any paid transactions go through the
  marketplace.
- **Privacy-mailbox forwarding fix.** When `ADMIN_NOTIFICATION_EMAIL`
  points at a same-domain alias (e.g. `privacy@occasions.london`), the
  Resend → Cloudflare Email Routing → Gmail forwarding can drop the
  message (DKIM/SPF break on the forwarder). Workaround: read receipts
  in the Resend Logs dashboard, or point `ADMIN_NOTIFICATION_EMAIL` at
  a personal external inbox.
