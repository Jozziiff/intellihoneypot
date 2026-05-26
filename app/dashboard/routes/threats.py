from __future__ import annotations

from collections import Counter

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.session.manager import SessionManager
from app.session.models import AttackPhase

router = APIRouter()


def setup_threats_router(session_mgr: SessionManager) -> APIRouter:
    @router.get("/api/threats")
    async def get_threats() -> JSONResponse:
        all_sessions = await session_mgr.list_active()
        # Exclude bare TCP probes: SSH sessions that never authenticated
        sessions = [s for s in all_sessions if s.command_history or s.service != "ssh"]
        phase_counts: Counter[str] = Counter()
        service_counts: Counter[str] = Counter()
        ip_counts: Counter[str] = Counter()

        for s in sessions:
            phase_counts[s.phase.value] += 1
            service_counts[s.service] += 1
            ip_counts[s.attacker_ip] += 1

        return JSONResponse({
            "total_sessions": len(sessions),
            "phases": {
                phase.value: phase_counts.get(phase.value, 0)
                for phase in AttackPhase
            },
            "services": dict(service_counts),
            "top_ips": [
                {"ip": ip, "count": count}
                for ip, count in ip_counts.most_common(10)
            ],
        })

    return router
