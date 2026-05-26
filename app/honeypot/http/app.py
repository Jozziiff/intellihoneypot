"""
HTTP honeypot — FastAPI app factory.

Mounts three routers, in this order (order matters: the catch-all MUST be last):
    1. VPN portal      — fake GlobalProtect login page (the primary lure).
    2. API mock        — `/api/*` endpoints returning plausible JSON errors.
    3. Scanner sink    — catch-all 404/403 for Nikto, Dirb, etc.

Two middlewares wrap every response:
    * HoneypotHeaderMiddleware — injects fake Apache/PHP headers.
    * RequestLoggerMiddleware  — emits one structured log line per request.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from app.honeypot.http.middleware import (
    HoneypotHeaderMiddleware,
    RequestLoggerMiddleware,
)
from app.honeypot.http.routes.api_mock import router as api_mock_router
from app.honeypot.http.routes.scanner_sink import router as scanner_sink_router
from app.honeypot.http.routes.vpn_portal import (
    router as vpn_router,
    setup_vpn_router,
)
from app.llm.orchestrator import LLMOrchestrator
from app.session.manager import SessionManager

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_http_app(session_mgr: SessionManager, llm: LLMOrchestrator) -> FastAPI:
    app = FastAPI(
        title="Honeypot HTTP",
        # Hide every FastAPI default that would betray our framework.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Middlewares run outside-in in registration order; the LAST `add_middleware`
    # call ends up innermost. The logger sees the bare response, the header
    # injector finishes last so its fake headers always survive.
    app.add_middleware(HoneypotHeaderMiddleware)
    app.add_middleware(RequestLoggerMiddleware)

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Routes — order matters: specific paths before the catch-all.
    setup_vpn_router(templates, session_mgr)
    app.include_router(vpn_router)
    app.include_router(api_mock_router)
    app.include_router(scanner_sink_router)  # catch-all MUST be last

    return app
