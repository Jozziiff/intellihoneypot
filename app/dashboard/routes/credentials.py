from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.session.manager import SessionManager

router = APIRouter()


def setup_credentials_router(session_mgr: SessionManager) -> APIRouter:
    @router.get("/api/credentials")
    async def get_credentials() -> JSONResponse:
        creds = await session_mgr.all_credentials()
        # Sort by most recent first
        creds.sort(key=lambda c: str(c.get("timestamp", "")), reverse=True)
        return JSONResponse(creds)

    return router
