from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_honeypots_api_returns_live_services(session_manager):
    from app.dashboard.app import create_dashboard_app

    app = create_dashboard_app(session_manager)
    await session_manager.create("1.2.3.4", "ssh", attacker_port=2222)
    await session_manager.create("5.6.7.8", "http", attacker_port=8080)

    with TestClient(app) as client:
        response = client.get("/api/honeypots")
        assert response.status_code == 200
        data = response.json()
        assert "honeypots" in data
        assert data["honeypots"]["ssh"]["status"] == "live"
        assert data["honeypots"]["ssh"]["active_sessions"] == 1
        assert data["honeypots"]["http"]["active_sessions"] == 1
        assert data["honeypots"]["ssh"]["port"] == 22
        assert data["honeypots"]["http"]["port"] == 80
