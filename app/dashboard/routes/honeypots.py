from __future__ import annotations

from collections import Counter

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.config import settings
from app.session.manager import SessionManager

router = APIRouter()

SERVICE_LABELS = {
    "ssh": "SSH Honeypot",
    "http": "HTTP VPN Portal",
}

SERVICE_DESCRIPTIONS = {
    "ssh": "Interactive fake shell with delayed bcrypt auth.",
    "http": "GlobalProtect-style portal capturing credential harvests.",
}


def setup_honeypots_router(session_mgr: SessionManager) -> APIRouter:
    @router.get("/api/honeypots")
    async def get_honeypots() -> JSONResponse:
        all_sessions = await session_mgr.list_active()
        result = {}

        for service in ("http", "ssh"):
            service_sessions = [s for s in all_sessions if s.service == service]
            phase_counts: Counter[str] = Counter(s.phase.value for s in service_sessions)
            last_seen = None
            if service_sessions:
                last_seen = max(s.last_seen for s in service_sessions).isoformat()

            result[service] = {
                "service": service,
                "label": SERVICE_LABELS[service],
                "description": SERVICE_DESCRIPTIONS[service],
                "port": getattr(settings, f"{service}_port"),
                "status": "live",
                "active_sessions": len(service_sessions),
                "last_seen": last_seen,
                "phase_counts": dict(phase_counts),
            }

        return JSONResponse({"honeypots": result})

    return router
