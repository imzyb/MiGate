"""Security headers middleware for MiGate."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to all responses."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
