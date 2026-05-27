from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import requests
from requests import RequestException

# Simple in-memory state for deduplication and brute-force counting.
# This is intentionally minimal; in production you might persist this in Redis.
_ALERT_DEDUP_SECONDS = 60
_login_failure_counts: dict[str, int] = {}
_last_alert_by_ip: dict[str, float] = {}

SUSPICIOUS_ENDPOINTS = ["/admin", "/wp-login", "/login", "/phpmyadmin"]


def _get_env(name: str) -> str | None:
    return os.environ.get(name)


def _is_suspicious_path(payload: str | None) -> bool:
    if not payload:
        return False
    normalized = payload.lower()
    return any(endpoint in normalized for endpoint in SUSPICIOUS_ENDPOINTS)


def _normalize_severity(severity: str | None) -> str:
    if not severity:
        return "LOW"
    sev = severity.strip().upper()
    return sev if sev in {"HIGH", "MEDIUM", "LOW"} else "LOW"


def _count_login_failure(ip: str, event_type: str, payload: str | None) -> int:
    if event_type != "login_failure" and (not payload or "login failed" not in payload.lower()):
        return 0

    count = _login_failure_counts.get(ip, 0) + 1
    _login_failure_counts[ip] = count
    return count


def _should_alert(event: dict[str, Any]) -> bool:
    ip = str(event.get("attacker_ip") or event.get("ip") or "unknown")
    event_type = str(event.get("event_type", "")).lower()
    payload = event.get("payload")
    severity = _normalize_severity(event.get("severity"))

    if severity == "HIGH":
        return True

    if _is_suspicious_path(payload):
        return True

    if event_type == "login_failure" or (isinstance(payload, str) and "login failed" in payload.lower()):
        if _count_login_failure(ip, event_type, payload) >= 5:
            return True

    return False


def _dedupe_alert(ip: str) -> bool:
    now = time.time()
    last_sent = _last_alert_by_ip.get(ip)
    if last_sent and now - last_sent < _ALERT_DEDUP_SECONDS:
        print(f"n8n_alert_skipped_dedup ip={ip} age={now-last_sent:.1f}s")
        return False
    _last_alert_by_ip[ip] = now
    return True


def _format_n8n_payload(event: dict[str, Any]) -> dict[str, Any]:
    # Map event fields to the payload expected by the n8n webhook
    ip = event.get("attacker_ip") or event.get("ip") or "unknown"
    # Detection time: try to normalize to `YYYY-MM-DD HH:MM:SS` for the template
    raw_ts = event.get("timestamp")
    if raw_ts:
        try:
            # Accept ISO format with or without trailing Z
            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except Exception:
            try:
                ts = datetime.utcfromtimestamp(float(raw_ts))
            except Exception:
                ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    detection_time = ts.strftime("%Y-%m-%d %H:%M:%S")
    severity = _normalize_severity(event.get("severity"))
    details = event.get("summary") or event.get("details") or event.get("payload") or ""

    # Human-readable message following the requested template
    message = (
        "HONEYPOT ALERT\n"
        "HONEYPOT ALERT - Security Event Detected\n\n"
        f"Event Type: {event.get('event_type')}\n"
        f"Source IP Address: {ip}\n"
        f"Detection Time: {detection_time}\n"
        f"Threat Severity Level: {severity}\n"
        f"Summary: {details}\n\n"
        "This alert was generated automatically by IntelliHoneypot. Please investigate immediately."
    )

    return {
        "event_type": event.get("event_type"),
        "ip": ip,
        "timestamp": detection_time,
        "severity": severity,
        "details": details,
    }


def send_whatsapp_alert(event: dict) -> None:
    """Send an alert to an n8n webhook (proxying WhatsApp). Never raises.

    The function keeps simple in-memory deduplication so the same IP
    doesn't trigger repeatedly within a short window.
    """
    try:
        # Send alerts for all events regardless of severity; keep deduplication.
        ip = str(event.get("attacker_ip") or event.get("ip") or "unknown")
        if not _dedupe_alert(ip):
            return

        webhook = _get_env("N8N_WEBHOOK_URL")
        if not webhook:
            print("N8N_WEBHOOK_URL not configured; skipping alert")
            return

        payload = _format_n8n_payload(event)

        try:
            resp = requests.post(webhook, json=payload, timeout=5)
            resp.raise_for_status()
            # For observability, print status and body (may be JSON)
            body = None
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            print(f"n8n webhook sent status={resp.status_code} body={body}")
        except RequestException as exc:
            print(f"n8n webhook request failed: {exc}")
    except Exception as exc:  # pragma: no cover - defensive
        # Must never crash the application
        print(f"Unexpected error while sending n8n webhook: {exc}")
        return
