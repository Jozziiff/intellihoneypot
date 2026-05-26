from __future__ import annotations

from datetime import datetime, timezone

from app.session.models import AttackPhase, Session, SessionEvent

_VENDOR = "IntelliHoneypot"
_PRODUCT = "HoneypotNode"
_VERSION = "1.0"

_SEVERITY_MAP: dict[AttackPhase, int] = {
    AttackPhase.RECON: 3,
    AttackPhase.BRUTE_FORCE: 6,
    AttackPhase.EXPLOITATION: 8,
    AttackPhase.PERSISTENCE: 9,
}

_SIG_MAP: dict[AttackPhase, tuple[str, str]] = {
    AttackPhase.RECON: ("100", "ReconActivity"),
    AttackPhase.BRUTE_FORCE: ("200", "BruteForceAttempt"),
    AttackPhase.EXPLOITATION: ("300", "ExploitAttempt"),
    AttackPhase.PERSISTENCE: ("400", "PersistenceAttempt"),
}


def _escape(value: str) -> str:
    """Escape CEF extension field values per the ArcSight specification."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", "")


class CEFFormatter:
    def format(self, session: Session, event: SessionEvent) -> str:
        """
        Build a CEF:0 formatted string.

        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        """
        phase = event.phase
        severity = _SEVERITY_MAP.get(phase, 3)
        sig_id, name = _SIG_MAP.get(phase, ("100", "HoneypotEvent"))

        # Extension key=value pairs
        ts = event.timestamp.strftime("%b %d %Y %H:%M:%S")
        ext_parts = [
            f"rt={ts}",
            f"src={_escape(session.attacker_ip)}",
            f"dpt={session.attacker_port}",
            f"suser={_escape(session.username)}",
            f"proto={_escape(session.service.upper())}",
            f"cs1Label=command",
            f"cs1={_escape(event.payload[:200])}",
            f"cs2Label=sessionId",
            f"cs2={_escape(session.session_id[:36])}",
            f"cat={_escape(phase.value)}",
        ]
        extension = " ".join(ext_parts)

        return (
            f"CEF:0|{_VENDOR}|{_PRODUCT}|{_VERSION}"
            f"|{sig_id}|{name}|{severity}|{extension}"
        )
