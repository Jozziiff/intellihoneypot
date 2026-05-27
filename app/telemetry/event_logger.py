from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.logging import get_logger
from app.session.models import AttackPhase, Session, SessionEvent
from app.telemetry.cef_formatter import CEFFormatter
from app.telemetry.classifier import ThreatClassifier
from app.telemetry.syslog_forwarder import UDPSyslogForwarder
from app.services.whatsapp_alert_service import send_whatsapp_alert

logger = get_logger(__name__)

_WRITE_LOCK = asyncio.Lock()


class EventLogger:
    """
    Central telemetry sink: classifies events, writes JSONL, and forwards CEF alerts.
    All writes are append-only so the file survives crashes without losing prior events.
    """

    def __init__(
        self,
        log_path: Path,
        forwarder: UDPSyslogForwarder,
        classifier: ThreatClassifier,
        cef_formatter: CEFFormatter,
    ) -> None:
        self._log_path = log_path
        self._forwarder = forwarder
        self._classifier = classifier
        self._cef = cef_formatter
        log_path.parent.mkdir(parents=True, exist_ok=True)

    async def log(
        self,
        session: Session,
        event_type: str,
        payload: str,
        **extra: str,
    ) -> SessionEvent:
        """Classify, persist to JSONL, and forward CEF alert. Returns the event."""
        new_phase = self._classifier.classify(payload, session.phase)
        session.phase = new_phase

        event = SessionEvent(
            event_type=event_type,
            payload=payload,
            phase=new_phase,
            extra={k: str(v) for k, v in extra.items()},
        )

        await self._write_jsonl(session, event)
        cef_msg = self._cef.format(session, event)
        await self._forwarder.send(cef_msg)

        await self._maybe_send_whatsapp_alert(session, event)

        logger.info(
            "event_logged",
            session_id=session.session_id,
            ip=session.attacker_ip,
            phase=new_phase.value,
            event_type=event_type,
        )

        return event

    async def _maybe_send_whatsapp_alert(self, session: Session, event: SessionEvent) -> None:
        alert_payload = {
            "event_type": event.event_type,
            "payload": event.payload,
            "attacker_ip": session.attacker_ip,
            "timestamp": event.timestamp.isoformat(),
            "severity": "HIGH" if event.phase.severity >= 8 else "MEDIUM" if event.phase.severity >= 6 else "LOW",
            "summary": event.extra.get("summary", event.payload),
            "phase": event.phase.value,
        }

        try:
            await asyncio.to_thread(send_whatsapp_alert, alert_payload)
        except Exception as exc:
            logger.warning(
                "whatsapp_alert_thread_failed",
                error=str(exc),
                session_id=session.session_id,
                ip=session.attacker_ip,
            )
            print(f"WhatsApp alert dispatch failed: {exc}")

    async def _write_jsonl(self, session: Session, event: SessionEvent) -> None:
        record = {
            "timestamp": event.timestamp.isoformat(),
            "session_id": session.session_id,
            "attacker_ip": session.attacker_ip,
            "service": session.service,
            "phase": event.phase.value,
            "event_type": event.event_type,
            "payload": event.payload,
            **event.extra,
        }
        line = json.dumps(record, ensure_ascii=False) + "\n"
        async with _WRITE_LOCK:
            with open(self._log_path, "a", encoding="utf-8", buffering=1) as f:
                f.write(line)
