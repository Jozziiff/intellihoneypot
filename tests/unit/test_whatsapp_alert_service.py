from __future__ import annotations

import os

import pytest

from app.services import whatsapp_alert_service


@pytest.fixture(autouse=True)
def clear_alert_state() -> None:
    whatsapp_alert_service._login_failure_counts.clear()
    whatsapp_alert_service._last_alert_by_ip.clear()


def test_send_whatsapp_alert_triggers_for_high_severity(monkeypatch):
    os.environ["N8N_WEBHOOK_URL"] = "https://example.com/webhook"

    captured = {}

    class DummyResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"ok": True}


    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return DummyResponse()

    monkeypatch.setattr(whatsapp_alert_service.requests, "post", fake_post)

    event = {
        "event_type": "http_login_attempt",
        "payload": "POST /login HTTP/1.1",
        "attacker_ip": "10.0.0.1",
        "timestamp": "2026-05-27T12:00:00Z",
        "severity": "HIGH",
    }

    # function returns None but should call the n8n webhook
    assert whatsapp_alert_service.send_whatsapp_alert(event) is None
    assert captured["url"] == "https://example.com/webhook"
    assert captured["json"]["event_type"] == "http_login_attempt"
    assert captured["json"]["ip"] == "10.0.0.1"
    assert captured["json"]["severity"] == "HIGH"


def test_send_whatsapp_alert_skips_duplicate_within_window(monkeypatch):
    os.environ["N8N_WEBHOOK_URL"] = "https://example.com/webhook"

    class DummyResponse:
        status_code = 200

        def raise_for_status(self):
            pass

    calls: list[dict] = []

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return DummyResponse()

    monkeypatch.setattr(whatsapp_alert_service.requests, "post", fake_post)

    event = {
        "event_type": "login_failure",
        "payload": "invalid password",
        "attacker_ip": "10.0.0.2",
        "timestamp": "2026-05-27T12:00:00Z",
        "severity": "LOW",
    }

    # First call should trigger immediately (new behavior: send every alert)
    assert whatsapp_alert_service.send_whatsapp_alert(event) is None
    assert len(calls) == 1

    # Subsequent immediate calls for the same IP should be deduped
    for _ in range(4):
        event["event_type"] = "login_failure"
        event["payload"] = "login failed"
        assert whatsapp_alert_service.send_whatsapp_alert(event) is None
        assert len(calls) == 1

    # After dedupe window passes we should be able to send again (simulate time)
    whatsapp_alert_service._last_alert_by_ip[event["attacker_ip"]] -= 61
    whatsapp_alert_service.send_whatsapp_alert(event)
    assert len(calls) == 2
