from __future__ import annotations

import httpx
import pytest


@pytest.mark.asyncio
async def test_dashboard_requires_login_for_overview(monkeypatch, session_manager):
    from app.config import settings
    from app.dashboard.app import create_dashboard_app

    monkeypatch.setattr(settings, "dashboard_admin_username", "admin", raising=False)
    monkeypatch.setattr(settings, "dashboard_admin_password", "secret", raising=False)
    monkeypatch.setattr(settings, "dashboard_secret_key", "test-secret", raising=False)

    app = create_dashboard_app(session_manager)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_dashboard_login_sets_session_cookie(monkeypatch, session_manager):
    from app.config import settings
    from app.dashboard.app import create_dashboard_app

    monkeypatch.setattr(settings, "dashboard_admin_username", "admin", raising=False)
    monkeypatch.setattr(settings, "dashboard_admin_password", "secret", raising=False)
    monkeypatch.setattr(settings, "dashboard_secret_key", "test-secret", raising=False)

    app = create_dashboard_app(session_manager)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/login", data={"username": "admin", "password": "secret"})

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "dashboard_session=" in response.headers["set-cookie"]


@pytest.mark.asyncio
async def test_dashboard_api_requires_auth(monkeypatch, session_manager):
    from app.config import settings
    from app.dashboard.app import create_dashboard_app

    monkeypatch.setattr(settings, "dashboard_admin_username", "admin", raising=False)
    monkeypatch.setattr(settings, "dashboard_admin_password", "secret", raising=False)
    monkeypatch.setattr(settings, "dashboard_secret_key", "test-secret", raising=False)

    app = create_dashboard_app(session_manager)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/honeypots")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"
