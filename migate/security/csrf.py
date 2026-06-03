"""CSRF protection middleware for MiGate panel."""
from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class CSRFMiddleware(BaseHTTPMiddleware):
    """Require CSRF token for state-changing panel requests.

    API endpoints (/api/, /sub/) are exempt — they use session cookies
    but are consumed by JS fetch calls that already set x-csrf-token.

    Login/logout are exempt — they carry their own credentials.

    Enforcement strategy:
    - If no session cookie → allow (not logged in)
    - If CSRF header token matches → allow
    - If no Origin/Referer header → allow (same-origin form submit or curl)
    - If Origin/Referer matches host → allow (same-origin)
    - Otherwise → block (cross-site request)

    Note: We do NOT read the request body to avoid consuming it before
    FastAPI's form parsing. The x-csrf-token header is the primary token
    channel for JS fetch calls.
    """

    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
    EXEMPT_PREFIXES = ("/api/", "/sub/")
    EXEMPT_PATHS = ("/login", "/logout")

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in self.EXEMPT_PREFIXES):
            return await call_next(request)
        if any(path.endswith(p) for p in self.EXEMPT_PATHS):
            return await call_next(request)

        session_cookie = request.cookies.get("migate_session", "")
        if not session_cookie:
            # Not logged in — CSRF doesn't apply
            return await call_next(request)

        cookie_token = request.cookies.get("migate_csrf", "")
        if not cookie_token:
            return await call_next(request)

        # Check 1: CSRF header token match (for JS fetch calls)
        header_token = request.headers.get("x-csrf-token", "")
        if header_token and header_token == cookie_token:
            return await call_next(request)

        # Check 2: No Origin/Referer = likely same-origin form submit or non-browser client
        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")
        if not origin and not referer:
            return await call_next(request)

        # Check 3: Same-origin (Origin/Referer matches request host)
        host = request.headers.get("host", "")
        if host:
            for header_val in (origin, referer):
                if header_val and (
                    header_val.startswith(f"http://{host}")
                    or header_val.startswith(f"https://{host}")
                ):
                    return await call_next(request)

        return JSONResponse({"detail": "CSRF token mismatch"}, status_code=403)


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_hex(32)
