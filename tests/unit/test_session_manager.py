"""Unit tests for SessionManager."""
import pytest
from app.session.models import AttackPhase, CapturedCredential, SessionEvent


@pytest.mark.asyncio
async def test_create_and_get(session_manager):
    session = await session_manager.create("1.2.3.4", "ssh")
    fetched = await session_manager.get(session.session_id)
    assert fetched.attacker_ip == "1.2.3.4"
    assert fetched.service == "ssh"


@pytest.mark.asyncio
async def test_list_active(session_manager):
    await session_manager.create("1.1.1.1", "ssh")
    await session_manager.create("2.2.2.2", "http")
    sessions = await session_manager.list_active()
    ips = {s.attacker_ip for s in sessions}
    assert "1.1.1.1" in ips
    assert "2.2.2.2" in ips


@pytest.mark.asyncio
async def test_update_phase(session_manager):
    session = await session_manager.create("3.3.3.3", "ssh")
    session.phase = AttackPhase.EXPLOITATION
    await session_manager.update(session)
    fetched = await session_manager.get(session.session_id)
    assert fetched.phase == AttackPhase.EXPLOITATION


@pytest.mark.asyncio
async def test_capture_credential(session_manager):
    session = await session_manager.create("4.4.4.4", "ssh")
    cred = CapturedCredential(username="root", password="toor", service="ssh", method="password_auth")
    await session_manager.capture_credential(session.session_id, cred)
    fetched = await session_manager.get(session.session_id)
    assert len(fetched.captured_credentials) == 1
    assert fetched.captured_credentials[0].username == "root"


@pytest.mark.asyncio
async def test_delete_removes_session(session_manager):
    from app.core.exceptions import SessionNotFoundError
    session = await session_manager.create("5.5.5.5", "ssh")
    await session_manager.delete(session.session_id)
    with pytest.raises(SessionNotFoundError):
        await session_manager.get(session.session_id)


@pytest.mark.asyncio
async def test_append_event(session_manager):
    session = await session_manager.create("6.6.6.6", "ssh")
    event = SessionEvent(event_type="command", payload="ls", phase=AttackPhase.RECON)
    await session_manager.append_event(session.session_id, event)
    fetched = await session_manager.get(session.session_id)
    assert len(fetched.events) == 1
    assert fetched.events[0].payload == "ls"
