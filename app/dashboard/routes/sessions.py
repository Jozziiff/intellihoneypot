from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.session.manager import SessionManager

router = APIRouter()


def setup_sessions_router(session_mgr: SessionManager) -> APIRouter:
    @router.get("/api/sessions")
    async def get_sessions() -> JSONResponse:
        all_sessions = await session_mgr.list_active()
        sessions = [s for s in all_sessions if s.command_history or s.service != "ssh"]
        return JSONResponse([
            {
                "session_id": s.session_id,
                "attacker_ip": s.attacker_ip,
                "service": s.service,
                "phase": s.phase.value,
                "started_at": s.started_at.isoformat(),
                "last_seen": s.last_seen.isoformat(),
                "command_count": len(s.command_history),
                "username": s.username,
                "current_dir": s.current_dir,
            }
            for s in sessions
        ])

    @router.get("/api/sessions/{session_id}")
    async def get_session_detail(session_id: str) -> JSONResponse:
        from app.core.exceptions import SessionNotFoundError
        try:
            s = await session_mgr.get(session_id)
            return JSONResponse({
                "session_id": s.session_id,
                "attacker_ip": s.attacker_ip,
                "service": s.service,
                "phase": s.phase.value,
                "started_at": s.started_at.isoformat(),
                "last_seen": s.last_seen.isoformat(),
                "current_dir": s.current_dir,
                "username": s.username,
                "command_history": s.command_history,
                "events": [e.model_dump() for e in s.events[-50:]],
            })
        except SessionNotFoundError:
            return JSONResponse({"error": "Not found"}, status_code=404)

    return router
