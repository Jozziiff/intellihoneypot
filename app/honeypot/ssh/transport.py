"""
SSH TransportManager — bridges Paramiko (threaded) with asyncio.

Paramiko handles SSH transport on its own threads. The rest of our app is
asyncio (Redis, LLM, HTTP). To live together, every Paramiko handler runs
on a `ThreadPoolExecutor` and uses `run_coroutine_threadsafe()` to call
back into the asyncio loop.

Connection lifecycle:
    1. asyncio `sock_accept()` returns a new TCP socket.
    2. We bump the active-session count (capped at SSH_MAX_SESSIONS).
    3. We hand the socket to the executor → `_handle_client()`.
    4. That thread spins up a Paramiko Transport, waits for auth + shell,
       then bounces the FakeShell coroutine back onto the asyncio loop.
    5. When the connection ends we decrement the counter and purge any
       "empty" session that never ran a single command (port scanners).
"""
from __future__ import annotations

import asyncio
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import paramiko

from app.config import settings
from app.core.logging import get_logger
from app.honeypot.ssh.auth import SSHAuthHandler
from app.honeypot.ssh.server import HoneypotSSHServer
from app.honeypot.ssh.shell import FakeShell
from app.llm.orchestrator import LLMOrchestrator
from app.session.manager import SessionManager
from app.session.virtual_fs import VirtualFilesystem

logger = get_logger(__name__)

# Module-level set of currently-active session IDs.
# Protected by a Lock because Paramiko worker threads mutate it.
_ACTIVE_SESSIONS: set[str] = set()
_SESSIONS_LOCK = threading.Lock()


class TransportManager:
    """Accepts TCP connections and hands them off to Paramiko transports."""

    def __init__(
        self,
        session_mgr: SessionManager,
        fs: VirtualFilesystem,
        llm: LLMOrchestrator,
        host_key: paramiko.RSAKey,
    ) -> None:
        self._session_mgr = session_mgr
        self._fs = fs
        self._llm = llm
        self._host_key = host_key
        self._auth_handler = SSHAuthHandler()
        # One thread per concurrent SSH session, hard-capped to keep memory
        # bounded on the Raspberry Pi target.
        self._executor = ThreadPoolExecutor(max_workers=settings.ssh_max_sessions)

    async def start(self, host: str = "0.0.0.0", port: int = 22) -> None:
        """Bind the listener and accept forever."""
        loop = asyncio.get_running_loop()
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        server_sock.bind((host, port))
        server_sock.listen(50)
        server_sock.setblocking(False)

        logger.info("ssh_listening", host=host, port=port)

        while True:
            client_sock, addr = await loop.sock_accept(server_sock)
            attacker_ip, attacker_port = addr

            with _SESSIONS_LOCK:
                if len(_ACTIVE_SESSIONS) >= settings.ssh_max_sessions:
                    # Saturated — drop the new connection without paying the
                    # cost of spinning up a Paramiko transport.
                    await loop.run_in_executor(
                        self._executor,
                        self._reject_connection,
                        client_sock,
                        attacker_ip,
                    )
                    continue

            logger.info("ssh_connection", ip=attacker_ip, port=attacker_port)
            await loop.run_in_executor(
                self._executor,
                self._handle_client,
                client_sock,
                attacker_ip,
                attacker_port,
                loop,
            )

    def _reject_connection(self, sock: socket.socket, ip: str) -> None:
        try:
            sock.close()
        except OSError:
            pass
        logger.warning("ssh_max_sessions_reached", ip=ip)

    def _handle_client(
        self,
        sock: socket.socket,
        attacker_ip: str,
        attacker_port: int,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """
        Runs on a ThreadPoolExecutor worker. Pure blocking code — uses
        `run_coroutine_threadsafe` to talk back to the asyncio world.
        """
        session_id: str | None = None
        try:
            # Create the Session via the asyncio SessionManager.
            session = asyncio.run_coroutine_threadsafe(
                self._session_mgr.create(attacker_ip, "ssh", attacker_port), loop
            ).result(timeout=5)

            session_id = session.session_id
            with _SESSIONS_LOCK:
                _ACTIVE_SESSIONS.add(session_id)

            # Set up the Paramiko transport.
            transport = paramiko.Transport(sock)
            transport.add_server_key(self._host_key)
            transport.banner_timeout = 10
            transport.auth_timeout = 30

            server = HoneypotSSHServer(
                self._auth_handler, session, self._session_mgr, loop
            )
            transport.start_server(server=server)

            # Wait for the client to ask for a shell (up to 30 s).
            server.event.wait(timeout=30)
            if not server.event.is_set():
                return

            channel = transport.accept(30)
            if channel is None:
                return

            # Run the fake shell on the asyncio loop, and block this thread
            # until the shell coroutine returns.
            asyncio.run_coroutine_threadsafe(
                FakeShell(
                    channel,
                    session,
                    self._session_mgr,
                    self._fs,
                    self._llm,
                ).run(),
                loop,
            ).result()

        except Exception as exc:
            logger.error("ssh_handler_error", ip=attacker_ip, error=str(exc))
        finally:
            if session_id:
                with _SESSIONS_LOCK:
                    _ACTIVE_SESSIONS.discard(session_id)
                # Bare TCP probes and port scanners open a connection, never
                # run any command, then drop. Purging those keeps the
                # dashboard "Recent Sessions" list signal-heavy.
                try:
                    s = asyncio.run_coroutine_threadsafe(
                        self._session_mgr.get(session_id), loop
                    ).result(timeout=2)
                    if not s.command_history:
                        asyncio.run_coroutine_threadsafe(
                            self._session_mgr.delete(session_id), loop
                        ).result(timeout=2)
                except Exception:
                    pass
            try:
                sock.close()
            except OSError:
                pass
