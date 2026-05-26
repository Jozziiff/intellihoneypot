"""
Fake `/api/*` endpoints.

Attackers like to probe well-known API paths (`/api/users`, `/api/config`,
`/api/health`) hoping to find a leaky JSON endpoint. We return plausible
errors and one healthy response, so the surface looks like a stripped-down
REST API behind authentication.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api")


@router.get("/v1/users", include_in_schema=False)
@router.get("/v2/users", include_in_schema=False)
async def fake_users(request: Request) -> JSONResponse:
    logger.info("api_probe", endpoint="/api/users", ip=_ip(request))
    return JSONResponse({"error": "Unauthorized", "code": 401}, status_code=401)


@router.get("/v1/config", include_in_schema=False)
@router.get("/config", include_in_schema=False)
async def fake_config(request: Request) -> JSONResponse:
    logger.info("api_probe", endpoint="/api/config", ip=_ip(request))
    return JSONResponse({"error": "Forbidden", "code": 403}, status_code=403)


@router.get("/health", include_in_schema=False)
async def health(request: Request) -> JSONResponse:
    # One endpoint returns 200 with a fake version string — makes the API
    # look real (monitoring probes hit /health constantly on real apps).
    return JSONResponse({"status": "ok", "version": "5.2.13"})


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def api_catch_all(request: Request, path: str) -> JSONResponse:
    logger.info("api_probe", endpoint=f"/api/{path}", ip=_ip(request))
    return JSONResponse({"error": "Not Found", "code": 404}, status_code=404)


def _ip(request: Request) -> str:
    """Best-effort attacker IP — same logic as the other modules."""
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
