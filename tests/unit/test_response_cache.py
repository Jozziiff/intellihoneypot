"""Unit tests for ResponseCache."""
import pytest


@pytest.mark.asyncio
async def test_cache_miss_returns_none(response_cache):
    result = await response_cache.get("ls -la", "context1")
    assert result is None


@pytest.mark.asyncio
async def test_set_and_get(response_cache):
    await response_cache.set("whoami", "context1", "admin")
    result = await response_cache.get("whoami", "context1")
    assert result == "admin"


@pytest.mark.asyncio
async def test_different_context_different_key(response_cache):
    await response_cache.set("whoami", "ctx_a", "admin")
    result = await response_cache.get("whoami", "ctx_b")
    assert result is None


@pytest.mark.asyncio
async def test_invalidate(response_cache):
    await response_cache.set("pwd", "ctx", "/home/admin")
    await response_cache.invalidate("pwd", "ctx")
    result = await response_cache.get("pwd", "ctx")
    assert result is None


@pytest.mark.asyncio
async def test_flush_all(response_cache):
    await response_cache.set("cmd1", "ctx", "output1")
    await response_cache.set("cmd2", "ctx", "output2")
    deleted = await response_cache.flush_all()
    assert deleted >= 2
    assert await response_cache.get("cmd1", "ctx") is None
