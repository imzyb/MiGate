"""Tests for MiGate security modules."""
from __future__ import annotations

import time

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from migate.security.csrf import CSRFMiddleware, generate_csrf_token
from migate.security.headers import SecurityHeadersMiddleware
from migate.security.rate_limit import LoginRateLimiter


# ── CSRF ────────────────────────────────────────────────────────────────

class TestCSRFToken:
    def test_generate_returns_hex_string(self):
        token = generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) == 64  # 32 bytes hex
        int(token, 16)  # should not raise

    def test_generate_unique(self):
        tokens = {generate_csrf_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_middleware_allows_get(self):
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/test", ok, methods=["GET"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200

    def test_middleware_allows_api_post(self):
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/api/test", ok, methods=["POST"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        resp = client.post("/api/test")
        assert resp.status_code == 200

    def test_middleware_allows_sub_get(self):
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/sub/{token}", ok, methods=["GET"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        resp = client.get("/sub/abc123")
        assert resp.status_code == 200

    def test_middleware_allows_post_without_csrf_cookie(self):
        """No csrf cookie → first visit / non-browser → allow."""
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/migate/test", ok, methods=["POST"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        resp = client.post("/migate/test")
        assert resp.status_code == 200

    def test_middleware_blocks_cross_origin_with_mismatched_token(self):
        """POST from a different origin with csrf cookie but no matching header should be blocked."""
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/migate/test", ok, methods=["POST"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        client.cookies.set("migate_csrf", "valid_token_123")
        client.cookies.set("migate_session", "session_abc")
        resp = client.post("/migate/test", headers={"origin": "https://evil.com"})
        assert resp.status_code == 403

    def test_middleware_allows_post_with_matching_header(self):
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/migate/test", ok, methods=["POST"])])
        app.add_middleware(CSRFMiddleware)
        client = TestClient(app)
        client.cookies.set("migate_csrf", "valid_token_123")
        resp = client.post("/migate/test", headers={"x-csrf-token": "valid_token_123"})
        assert resp.status_code == 200


# ── Rate Limiter ────────────────────────────────────────────────────────

class TestRateLimiter:
    def test_allows_first_attempts(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check("1.2.3.4") is True
            limiter.record("1.2.3.4")

    def test_blocks_after_max(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            limiter.record("1.2.3.4")
        assert limiter.check("1.2.3.4") is False

    def test_different_ips_independent(self):
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)
        limiter.record("1.1.1.1")
        limiter.record("1.1.1.1")
        assert limiter.check("1.1.1.1") is False
        assert limiter.check("2.2.2.2") is True

    def test_remaining_decreases(self):
        limiter = LoginRateLimiter(max_attempts=5, window_seconds=60)
        assert limiter.remaining("1.2.3.4") == 5
        limiter.record("1.2.3.4")
        assert limiter.remaining("1.2.3.4") == 4

    def test_window_expiry_resets(self):
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=1)
        limiter.record("1.2.3.4")
        limiter.record("1.2.3.4")
        assert limiter.check("1.2.3.4") is False
        time.sleep(1.1)
        assert limiter.check("1.2.3.4") is True


# ── Security Headers ────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_headers_present(self):
        async def ok(request: Request):
            return PlainTextResponse("ok")
        app = Starlette(routes=[Route("/test", ok)])
        app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(app)
        resp = client.get("/test")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["X-XSS-Protection"] == "1; mode=block"
        assert "strict-origin" in resp.headers["Referrer-Policy"]
