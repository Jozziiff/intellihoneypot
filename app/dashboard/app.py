from __future__ import annotations

import asyncio
import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.config import settings
from app.dashboard.routes.credentials import router as creds_router, setup_credentials_router
from app.dashboard.routes.sessions import router as sessions_router, setup_sessions_router
from app.dashboard.routes.threats import router as threats_router, setup_threats_router
from app.session.manager import SessionManager

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_dashboard_app(session_mgr: SessionManager) -> FastAPI:
    app = FastAPI(
        title="IntelliHoneypot Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Wire up API routers
    setup_sessions_router(session_mgr)
    setup_threats_router(session_mgr)
    setup_credentials_router(session_mgr)
    app.include_router(sessions_router)
    app.include_router(threats_router)
    app.include_router(creds_router)

    # Health check
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    # Page routes
    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html", {"active": "overview"})

    @app.get("/sessions", response_class=HTMLResponse)
    async def sessions_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "sessions.html", {"active": "sessions"})

    @app.get("/credentials", response_class=HTMLResponse)
    async def credentials_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "credentials.html", {"active": "credentials"})

    # WebSocket — pushes session updates every 5 seconds
    @app.websocket("/ws/sessions")
    async def ws_sessions(websocket: WebSocket) -> None:
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
