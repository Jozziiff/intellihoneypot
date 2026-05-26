"""
IntelliHoneypot — Application Entry Point

Starts SSH honeypot, HTTP honeypot, and optionally the mesh broadcaster/listener
as concurrent asyncio tasks using Python 3.11's TaskGroup for structured concurrency.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import paramiko
import uvicorn

from app.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.redis_client import close_redis_pool, create_redis_pool
from app.dashboard.app import create_dashboard_app
from app.honeypot.http.app import create_http_app
from app.honeypot.ssh.transport import TransportManager
from app.llm.cache import ResponseCache
from app.llm.guardrails import InputGuardrail
from app.llm.orchestrator import LLMOrchestrator
from app.llm.prompt_builder import PromptBuilder
from app.session.manager import SessionManager
from app.session.virtual_fs import VirtualFilesystem
from app.telemetry.cef_formatter import CEFFormatter
from app.telemetry.classifier import ThreatClassifier
from app.telemetry.event_logger import EventLogger
from app.telemetry.syslog_forwarder import UDPSyslogForwarder

logger = get_logger(__name__)

_CONFIG_DIR = Path("config")
_KEYS_DIR = Path("keys")
_LOGS_DIR = Path("logs")


async def main() -> None:
    configure_logging()
    logger.info("intellihoneypot_starting", version="0.1.0")

    # ── Shared Infrastructure ─────────────────────────────────────────────────
    redis = await create_redis_pool(settings.redis_url)
    session_mgr = SessionManager(redis)

    # ── Session & Filesystem ──────────────────────────────────────────────────
    fs = VirtualFilesystem(_CONFIG_DIR / "fake_fs.json")

    # ── LLM Stack ─────────────────────────────────────────────────────────────
    cache = ResponseCache(redis, settings.cache_ttl_seconds)
    guardrail = InputGuardrail()
    prompt_builder = PromptBuilder(_CONFIG_DIR / "persona_ssh.yaml")
    llm = LLMOrchestrator(cache, guardrail, prompt_builder, settings)

    # ── Telemetry ─────────────────────────────────────────────────────────────
    _LOGS_DIR.mkdir(exist_ok=True)
    forwarder = UDPSyslogForwarder(settings.syslog_host, settings.syslog_port)
    classifier = ThreatClassifier()
    cef = CEFFormatter()
    event_logger = EventLogger(_LOGS_DIR / "events.jsonl", forwarder, classifier, cef)

    # ── SSH Host Key ──────────────────────────────────────────────────────────
    key_path = _KEYS_DIR / "host_rsa"
    if not key_path.exists():
        logger.warning("host_key_missing", path=str(key_path), hint="run make gen-key")
        # Generate on-the-fly so the container still starts
        host_key = paramiko.RSAKey.generate(2048)
        _KEYS_DIR.mkdir(exist_ok=True)
        host_key.write_private_key_file(str(key_path))
    else:
        host_key = paramiko.RSAKey(filename=str(key_path))

    # ── Service Factories ─────────────────────────────────────────────────────
    ssh_transport = TransportManager(session_mgr, fs, llm, host_key)
    http_app = create_http_app(session_mgr, llm)
    dashboard_app = create_dashboard_app(session_mgr)

    http_config = uvicorn.Config(
        http_app,
        host="0.0.0.0",
        port=settings.http_port,
        log_level="warning",
        access_log=False,
    )
    dashboard_config = uvicorn.Config(
        dashboard_app,
        host="0.0.0.0",
        port=settings.dashboard_port,
        log_level="warning",
        access_log=False,
    )

    logger.info(
        "services_ready",
        ssh_port=settings.ssh_port,
        http_port=settings.http_port,
        dashboard_port=settings.dashboard_port,
        mesh_enabled=settings.mesh_enabled,
    )

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(ssh_transport.start("0.0.0.0", settings.ssh_port))
            tg.create_task(uvicorn.Server(http_config).serve())
            tg.create_task(uvicorn.Server(dashboard_config).serve())

            if settings.mesh_enabled:
                from app.mesh.broadcaster import MeshBroadcaster
                from app.mesh.listener import MeshListener

                broadcaster = MeshBroadcaster(
                    settings.mesh_multicast_group, settings.mesh_port, session_mgr
                )
                listener = MeshListener(
                    settings.mesh_multicast_group, settings.mesh_port, redis
                )
                tg.create_task(broadcaster.start())
                tg.create_task(listener.start())

    finally:
        await llm.close()
        await close_redis_pool()
        logger.info("intellihoneypot_stopped")


if __name__ == "__main__":
    asyncio.run(main())
