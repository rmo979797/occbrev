"""HTTP Basic Auth gate for the admin endpoint.

Pre-launch only collects waitlist signups, so we don't need a full JWT/user
table just to let one person export a CSV. Basic Auth over HTTPS (Cloudflare
gives us this for free) is enough.

Credentials live in env vars (ADMIN_USER / ADMIN_PASS). In production we
hard-refuse the default password to avoid the classic "deployed without
changing the default" foot-gun.
"""
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from config import settings


_basic = HTTPBasic(auto_error=False)


def require_admin(credentials: HTTPBasicCredentials | None = Depends(_basic)) -> str:
    # Defence-in-depth: even if env vars weren't set in prod, refuse to grant
    # access using the default values.
    if (
        settings.ENVIRONMENT == "production"
        and settings.ADMIN_PASS == "change-me-in-production"
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="admin credentials not configured",
        )
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    # secrets.compare_digest is constant-time — defends against timing attacks
    # that would otherwise leak the admin username one byte at a time.
    ok_user = secrets.compare_digest(credentials.username.encode(), settings.ADMIN_USER.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), settings.ADMIN_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
