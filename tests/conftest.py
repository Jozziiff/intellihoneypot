"""Shared pytest fixtures for unit and integration tests."""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# In-memory Redis (no running server required for unit tests)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def fake_redis():
    """fakeredis async client — fully compatible with redis.asyncio.Redis."""
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


# ---------------------------------------------------------------------------
# SessionManager backed by fake Redis
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def session_manager(fake_redis):
    from app.session.manager import SessionManager
    return SessionManager(fake_redis)


# ---------------------------------------------------------------------------
# VirtualFilesystem from real config file
# ---------------------------------------------------------------------------

@pytest.fixture
def virtual_fs():
    from app.session.virtual_fs import VirtualFilesystem
    config_path = Path(__file__).parent.parent / "config" / "fake_fs.json"
    return VirtualFilesystem(config_path)


# ---------------------------------------------------------------------------
# LLM components (no network required)
# ---------------------------------------------------------------------------

@pytest.fixture
def guardrail():
    from app.llm.guardrails import InputGuardrail
    return InputGuardrail()


@pytest_asyncio.fixture
async def response_cache(fake_redis):
    from app.llm.cache import ResponseCache
    return ResponseCache(fake_redis, ttl=60)


# ---------------------------------------------------------------------------
# Telemetry components
# ---------------------------------------------------------------------------

@pytest.fixture
def classifier():
    from app.telemetry.classifier import ThreatClassifier
    return ThreatClassifier()


@pytest.fixture
def cef_formatter():
    from app.telemetry.cef_formatter import CEFFormatter
    return CEFFormatter()
