"""
Paramiko `ServerInterface` implementation for the honeypot.

Paramiko calls these methods from its own worker thread for every SSH
connection. We use them to:
  * Accept any password (after a fake bcrypt delay).
  * Accept any public key.
  * Hand off control to the asyncio shell as soon as the client opens a
    PTY + shell.

The `event` Event is signalled when the client requests a shell, which
tells TransportManager it's safe to start running FakeShell.
"""
from __future__ import annotations

import asyncio
import threading

import paramiko

from app.core.logging import get_logger
from app.honeypot.ssh.auth import SSHAuthHandler
from app.session.manager import SessionManager
from app.session.models import Session

logger = get_logger(__name__)


class HoneypotSSHServer(paramiko.ServerInterface):
    """One instance per TCP connection (created by TransportManager)."""

    def __init__(
        self,
        auth_handler: SSHAuthHandler,
        session: Session,
        session_mgr: SessionManager,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._auth = auth_handler
        self._session = session
        self._session_mgr = session_mgr
        self._loop = loop  # the main asyncio loop — used for thread-safe scheduling

        # Set when the client asks for a shell (or exec). TransportManager
        # waits on this before calling `transport.accept()`.
        self.event = threading.Event()
        self._shell_channel: paramiko.Channel | None = None

    # ── Channel requests ──────────────────────────────────────────────────────

    def check_channel_request(self, kind: str, chanid: int) -> int:
        # Only allow "session" channels (the kind that opens shells/exec).
        # Refusing anything else (e.g. tcpip-forwarding) keeps the attack surface tight.
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self._shell_channel = channel
        self.event.set()  # unblock TransportManager
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        # Treat `ssh user@host "<cmd>"` exec mode the same as an interactive shell.
        self._shell_channel = channel
        self.event.set()
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True  # allow any PTY size — we ignore the dimensions

    def check_channel_window_change_request(
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        return True  # accept terminal resizes silently

    # ── Authentication ────────────────────────────────────────────────────────

    def get_allowed_auths(self, username: str) -> str:
        # Advertising both methods makes brute-forcers try password first
        # (the noisier behaviour, which is what we want to capture).
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        accepted, cred = self._auth.authenticate(
            username, password, self._session.attacker_ip
        )
        if accepted:
            self._session.username = username
            # We're on a Paramiko thread; bounce credential capture into the
            # asyncio loop so SessionManager can use its async Redis client.
            asyncio.run_coroutine_threadsafe(
                self._session_mgr.capture_credential(
                    self._session.session_id, cred
                ),
                self._loop,
            )
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Accept any key — log the attempt for forensics and move on.
        logger.info(
            "ssh_pubkey_attempt", username=username, key_type=key.get_name()
        )
        self._session.username = username
        return paramiko.AUTH_SUCCESSFUL
