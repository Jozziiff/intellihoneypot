"""
HTTP middlewares — header spoofing and request logging.

`HoneypotHeaderMiddleware` makes us look like an Apache/PHP server, which
is what most attackers expect when they see port 80. Mismatched headers
(e.g. "Server: uvicorn") would immediately tell anyone scanning that
they've hit something custom and back away.

`RequestLoggerMiddleware` writes a structured log line for every request,
which is the raw telemetry the dashboard feeds on.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import get_logger

logger = get_logger(__name__)

# Headers we want to send back. Chosen to match a default Apache + PHP setup
# on Ubuntu, since GlobalProtect-style portals typically run on that stack.
_FAKE_HEADERS = {
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.3",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class HoneypotHeaderMiddleware(BaseHTTPMiddleware):
    """Injects realistic Apache/PHP headers on every outgoing response."""

    async def dispatch(self, request: Request, call_next: object) -> Response:
        response: Response = await call_next(request)  # type: ignore[arg-type]

        for key, value in _FAKE_HEADERS.items():
            response.headers[key] = value

        # FastAPI sometimes emits this header — strip it so we don't leak
        # the framework name. Use `del` (not `.pop`) because Starlette's
        # MutableHeaders doesn't implement pop().
        if "x-application-context" in response.headers:
            del response.headers["x-application-context"]

        return response


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """Logs every incoming HTTP request with attacker metadata."""

    async def dispatch(self, request: Request, call_next: object) -> Response:
        # Prefer X-Forwarded-For (when behind a reverse proxy), then X-Real-IP,
        # then the raw TCP peer. This works in dev (no proxy) and in prod.
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.headers.get("x-real-ip", "")
            or (request.client.host if request.client else "unknown")
        )
        logger.info(
            "http_request",
            ip=client_ip,
            method=request.method,
            path=request.url.path,
            query=str(request.url.query),
            user_agent=request.headers.get("user-agent", ""),
        )
        response: Response = await call_next(request)  # type: ignore[arg-type]
        return response
