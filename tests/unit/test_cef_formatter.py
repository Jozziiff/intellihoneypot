"""Unit tests for CEFFormatter."""
import pytest
from app.session.models import AttackPhase, Session, SessionEvent


def test_cef_format_structure(cef_formatter):
    from datetime import datetime, timezone
    session = Session(attacker_ip="1.2.3.4", service="ssh", username="admin")
    event = SessionEvent(event_type="command", payload="ls -la", phase=AttackPhase.RECON)
    result = cef_formatter.format(session, event)
    assert result.startswith("CEF:0|IntelliHoneypot|HoneypotNode|1.0|")
    assert "src=1.2.3.4" in result
    assert "suser=admin" in result


def test_cef_exploitation_severity(cef_formatter):
    session = Session(attacker_ip="5.6.7.8", service="ssh", username="root")
    event = SessionEvent(event_type="command", payload="bash -i", phase=AttackPhase.EXPLOITATION)
    result = cef_formatter.format(session, event)
    # Severity for EXPLOITATION is 8
    assert "|8|" in result


def test_cef_persistence_severity(cef_formatter):
    session = Session(attacker_ip="5.6.7.8", service="http", username="admin")
    event = SessionEvent(event_type="command", payload="crontab -e", phase=AttackPhase.PERSISTENCE)
    result = cef_formatter.format(session, event)
    # Severity for PERSISTENCE is 9
    assert "|9|" in result


def test_cef_escapes_pipe_in_payload(cef_formatter):
    session = Session(attacker_ip="1.1.1.1", service="ssh", username="admin")
    event = SessionEvent(event_type="command", payload="cat file | grep pass", phase=AttackPhase.RECON)
    result = cef_formatter.format(session, event)
    # Pipe in extension value must be escaped
    assert "cat file \\| grep pass" in result
