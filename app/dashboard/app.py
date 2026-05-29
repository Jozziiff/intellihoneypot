from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.config import settings
from app.dashboard.routes.credentials import router as creds_router, setup_credentials_router
from app.dashboard.routes.honeypots import router as honeypots_router, setup_honeypots_router
from app.dashboard.routes.sessions import router as sessions_router, setup_sessions_router
from app.dashboard.routes.threats import router as threats_router, setup_threats_router
from app.session.manager import SessionManager

_SESSION_COOKIE_NAME = "dashboard_session"
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _sign_session_token(username: str, secret: str) -> str:
    signature = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{username}:{signature}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("utf-8")


def _verify_session_token(token: str, secret: str) -> str | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None

    try:
        username, signature = decoded.split(":", 1)
    except ValueError:
        return None

    expected_signature = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    return username


def _get_dashboard_user(request: Request | WebSocket) -> str | None:
    token = None
    if isinstance(request, Request):
        token = request.cookies.get(_SESSION_COOKIE_NAME)
    else:
        token = request.cookies.get(_SESSION_COOKIE_NAME)

    if not token:
        return None
    return _verify_session_token(token, settings.dashboard_secret_key)


def create_dashboard_app(session_mgr: SessionManager) -> FastAPI:
    app = FastAPI(
        title="IntelliHoneypot Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        if path in {"/health", "/login", "/logout"}:
            return await call_next(request)

        if _get_dashboard_user(request) is None:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
            return RedirectResponse(url="/login", status_code=303)

        return await call_next(request)

    # Wire up API routers
    setup_sessions_router(session_mgr)
    setup_threats_router(session_mgr)
    setup_credentials_router(session_mgr)
    setup_honeypots_router(session_mgr)
    app.include_router(sessions_router)
    app.include_router(threats_router)
    app.include_router(creds_router)
    app.include_router(honeypots_router)

    # Health check
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        if _get_dashboard_user(request):
            return RedirectResponse(url="/", status_code=303)
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> HTMLResponse:
        if _get_dashboard_user(request):
            return RedirectResponse(url="/", status_code=303)

        form = await request.form()
        username = (form.get("username") or "").strip()
        password = (form.get("password") or "").strip()

        if username != settings.dashboard_admin_username or password != settings.dashboard_admin_password:
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Invalid admin credentials"},
                status_code=401,
            )

        token = _sign_session_token(username, settings.dashboard_secret_key)
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            _SESSION_COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            path="/",
            max_age=3600,
        )
        return response

    @app.get("/logout", response_class=HTMLResponse)
    async def logout(request: Request) -> HTMLResponse:
        response = templates.TemplateResponse(request, "logout.html")
        response.delete_cookie(_SESSION_COOKIE_NAME, path="/")
        return response

    # Page routes
    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request) -> HTMLResponse:
        if _get_dashboard_user(request) is None:
            return RedirectResponse(url="/login", status_code=303)
        return templates.TemplateResponse(request, "index.html", {"active": "overview"})

    @app.get("/sessions", response_class=HTMLResponse)
    async def sessions_page(request: Request) -> HTMLResponse:
        if _get_dashboard_user(request) is None:
            return RedirectResponse(url="/login", status_code=303)
        return templates.TemplateResponse(request, "sessions.html", {"active": "sessions"})

    @app.get("/credentials", response_class=HTMLResponse)
    async def credentials_page(request: Request) -> HTMLResponse:
        if _get_dashboard_user(request) is None:
            return RedirectResponse(url="/login", status_code=303)
        return templates.TemplateResponse(request, "credentials.html", {"active": "credentials"})

    # WebSocket — pushes session updates every 5 seconds
    @app.websocket("/ws/sessions")
    async def ws_sessions(websocket: WebSocket) -> None:
        if _get_dashboard_user(websocket) is None:
            await websocket.close(code=4401)
            return

        await websocket.accept()
        try:
            while True:
                sessions = await session_mgr.list_active()
                data = [
                    {
                        "session_id": s.session_id,
                        "attacker_ip": s.attacker_ip,
                        "service": s.service,
                        "phase": s.phase.value,
                    }
                    for s in sessions
                ]
                await websocket.send_text(json.dumps(data))
                await asyncio.sleep(5)
        except WebSocketDisconnect:
            pass

    return app


if __name__ == "__main__":
    from app.config import settings
    from app.core.logging import configure_logging
    from app.core.redis_client import create_redis_pool

    async def _run() -> None:
        configure_logging()
        redis = await create_redis_pool(settings.redis_url)
        session_mgr = SessionManager(redis)
        app = create_dashboard_app(session_mgr)
        config = uvicorn.Config(
            app, host="0.0.0.0", port=settings.dashboard_port, log_level="info"
        )
        await uvicorn.Server(config).serve()

    asyncio.run(_run())
