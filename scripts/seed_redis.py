#!/usr/bin/env python3
"""
Pre-warm the LLM Redis cache with responses for the most common attacker commands.
Run once after 'make up' and 'make pull-models' to eliminate cold-start latency.

Usage: docker compose run --rm app python scripts/seed_redis.py
       or: make seed-cache
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import settings
from app.core.redis_client import close_redis_pool, create_redis_pool
from app.llm.cache import ResponseCache
from app.llm.guardrails import InputGuardrail
from app.llm.orchestrator import LLMOrchestrator
from app.llm.prompt_builder import PromptBuilder
from app.session.models import Session

_COMMON_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "ls -la",
    "ls -la /",
    "ls -la /home",
    "ls -la /var/www/html",
    "ps aux",
    "netstat -tulpn",
    "ifconfig",
    "cat /etc/os-release",
    "cat /proc/version",
    "df -h",
    "free -h",
    "w",
    "last",
    "find / -perm -4000 2>/dev/null",
    "sudo -l",
    "env",
    "history",
]


async def main() -> None:
    print("IntelliHoneypot — Cache Seeder")
    print("=" * 40)

    redis = await create_redis_pool(settings.redis_url)
    cache = ResponseCache(redis, settings.cache_ttl_seconds)
    guardrail = InputGuardrail()
    prompt_builder = PromptBuilder(Path("config/persona_ssh.yaml"))
    llm = LLMOrchestrator(cache, guardrail, prompt_builder, settings)

    # Use a synthetic session for seeding
    session = Session(attacker_ip="seeder", service="ssh", username="admin")

    seeded = 0
    errors = 0

    for cmd in _COMMON_COMMANDS:
        # Skip if already cached
        context = prompt_builder.context_string(session)
        if await cache.get(cmd, context) is not None:
            print(f"  SKIP (cached): {cmd}")
            continue

        try:
            response, _ = await llm.generate(cmd, session)
            session.command_history.append(cmd)
            print(f"  OK: {cmd!r} → {response[:60]!r}...")
            seeded += 1
        except Exception as exc:
            print(f"  ERR: {cmd!r} — {exc}")
            errors += 1

    await llm.close()
    await close_redis_pool()

    print()
    print(f"Done. Seeded: {seeded}, Errors: {errors}, Skipped: {len(_COMMON_COMMANDS) - seeded - errors}")


if __name__ == "__main__":
    asyncio.run(main())
