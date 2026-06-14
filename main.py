"""Occasions waitlist — standalone FastAPI app.

Isolated from the main marketplace deliberately: this server only knows
about waitlist signups. No user accounts, no payments, no uploads, no
inter-supplier messaging. If this box is compromised, the blast radius is
the waitlist table and nothing else.
"""
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from routes import waitlist


# ---------------------------------------------------------------------------
# Sentry (optional, only enabled when SENTRY_DSN is set)
# ---------------------------------------------------------------------------
if settings.SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            environment=settings.ENVIRONMENT,
            release=settings.APP_VERSION,
            integrations=[StarletteIntegration(), FastApiIntegration()],
            traces_sample_rate=0.05,
            send_default_pii=False,
        )
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Production safety: refuse to boot with default admin credentials.
# ---------------------------------------------------------------------------
_IS_PROD = settings.ENVIRONMENT == "production"
if _IS_PROD and settings.ADMIN_PASS == "change-me-in-production":
    raise RuntimeError(
        "ADMIN_PASS is set to the default value in production. "
        "Set ADMIN_USER and ADMIN_PASS via env vars before starting."
    )


FRONTEND_DIR = Path(__file__).parent / "frontend"

app = FastAPI(
    title="Occasions Waitlist",
    description="Pre-launch supplier waitlist for occasions.london",
    version=settings.APP_VERSION,
    docs_url=None if _IS_PROD else "/docs",     # hide /docs in prod
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
# Tight CSP — no third-party scripts/fonts/frames. The waitlist page uses
# only inline <style> and a self-hosted /static/waitlist.js. We allow
# 'unsafe-inline' for style-src only (the page uses an inline <style> block);
# no 'unsafe-inline' for scripts.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault("Content-Security-Policy", _CSP)
        if _IS_PROD:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# CORS — the public form posts same-origin, so we just allow occasions.london
# in prod and localhost in dev.
# ---------------------------------------------------------------------------
_allowed_origins = [
    "https://occasions.london",
    "https://www.occasions.london",
]
if not _IS_PROD:
    _allowed_origins.extend([
        "http://localhost", "http://localhost:3000", "http://localhost:8080",
        "http://127.0.0.1", "http://127.0.0.1:3000", "http://127.0.0.1:8080",
    ])

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,                # no cookies/auth from JS — keeps things simple
    allow_methods=["GET", "POST"],          # nothing else is needed
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app.include_router(waitlist.router)

# Static (waitlist.js etc.) — only the frontend/ directory, nothing else.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def root():
    """Serve the waitlist HTML — never cache it so reviewers always see latest copy."""
    return FileResponse(
        FRONTEND_DIR / "waitlist.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


# www → apex redirect (in case Cloudflare doesn't already redirect www.).
@app.get("/healthz")
def healthz():
    """Plain health check for Railway / uptime monitors. No DB hit so a DB
    outage doesn't take the box out of rotation when the form is still OK."""
    return {"ok": True, "service": "waitlist"}
