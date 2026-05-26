"""
LLM Orchestrator — turns an attacker command into a believable shell reply.

Flow on every unknown shell command:
    1. Sanitize input via InputGuardrail (drops prompt-injection attempts).
    2. Look up the (command + recent context) in the Redis cache.
    3. If cache miss, ask the first available LLM backend in priority order.
    4. Cache the response and return it.

Backend priority (auto mode):
    Grok ▶ Cerebras ▶ Ollama (only if enabled) ▶ OpenAI ▶ Anthropic

If `LLM_BACKEND` in the env is set to a specific provider, ONLY that provider
is tried — no fallback. This lets you A/B test cleanly during demos.

Grok / Cerebras / OpenAI all speak the same OpenAI-compatible REST API, so
we route them through a single `_call_openai_compatible()` helper.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any

import httpx

from app.config import Settings
from app.core.logging import get_logger
from app.llm.cache import ResponseCache
from app.llm.guardrails import InputGuardrail
from app.llm.prompt_builder import PromptBuilder
from app.session.models import Session

logger = get_logger(__name__)

_FALLBACK_RESPONSE = "bash: command not found"

# A zero-arg async callable returning a string — one per registered backend.
_BackendFn = Callable[[], Coroutine[Any, Any, str]]


class LLMOrchestrator:
    def __init__(
        self,
        cache: ResponseCache,
        guardrail: InputGuardrail,
        prompt_builder: PromptBuilder,
        settings: Settings,
    ) -> None:
        self._cache = cache
        self._guardrail = guardrail
        self._prompt_builder = prompt_builder
        self._settings = settings
        # Shared HTTP client for Ollama; cloud SDKs manage their own clients.
        self._http = httpx.AsyncClient(timeout=10.0)

    async def generate(self, command: str, session: Session) -> tuple[str, bool]:
        """
        Generate a shell response for `command`.

        Returns `(response_text, was_injected)`.
        `was_injected=True` tells the caller to escalate the session phase
        to EXPLOITATION (handled by FakeShell._dispatch).
        """
        safe_cmd, was_injected = self._guardrail.sanitize(command)
        context = self._prompt_builder.context_string(session)

        # 1. Cache — same command + same recent history ⇒ same answer.
        cached = await self._cache.get(safe_cmd, context)
        if cached is not None:
            return cached, was_injected

        # 2. Build system/user messages — splitting them improves LLM accuracy
        #    vs. one giant blob, because models are trained on this role split.
        system_prompt = self._prompt_builder.get_system_prompt(session)
        user_content = self._prompt_builder.build_user_message(safe_cmd, session)

        # 3. Try backends in order — first success wins.
        response: str | None = None
        for backend in self._get_backend_chain(system_prompt, user_content):
            try:
                response = await backend()
                break
            except Exception as exc:
                logger.warning(
                    "llm_backend_failed", backend=backend.__name__, reason=str(exc)
                )

        if response is None:
            logger.error("all_llm_backends_failed", command=safe_cmd)
            response = _FALLBACK_RESPONSE

        await self._cache.set(safe_cmd, context, response)
        return response, was_injected

    # ── Backend chain ─────────────────────────────────────────────────────────

    def _get_backend_chain(
        self, system_prompt: str, user_content: str
    ) -> list[_BackendFn]:
        """
        Build the ordered list of LLM backends to try.

        Each backend is a closure capturing the prompt; this keeps the call
        site of `generate()` clean (just `await backend()` in a loop).

        If `LLM_BACKEND` is pinned to one provider, only that one is returned.
        """
        selector = self._settings.llm_backend.lower().strip()
        pool: dict[str, _BackendFn] = {}

        # Each block below registers a backend ONLY if its API key is set.
        # We assign `.__name__` so log lines say "grok" instead of "_grok".

        if self._settings.grok_api_key:
            async def _grok() -> str:
                return await self._call_openai_compatible(
                    api_key=self._settings.grok_api_key,
                    base_url=self._settings.grok_base_url,
                    model=self._settings.grok_model,
                    system_prompt=system_prompt,
                    user_content=user_content,
                )
            _grok.__name__ = "grok"
            pool["grok"] = _grok

        if self._settings.cerebras_api_key:
            async def _cerebras() -> str:
                return await self._call_openai_compatible(
                    api_key=self._settings.cerebras_api_key,
                    base_url=self._settings.cerebras_base_url,
                    model=self._settings.cerebras_model,
                    system_prompt=system_prompt,
                    user_content=user_content,
                )
            _cerebras.__name__ = "cerebras"
            pool["cerebras"] = _cerebras

        if self._settings.ollama_enabled:
            async def _ollama() -> str:
                # Wrap in wait_for: local Ollama on a Pi can stall on cold-start.
                return await asyncio.wait_for(
                    self._call_ollama(system_prompt, user_content),
                    timeout=float(self._settings.ollama_timeout_secs),
                )
            _ollama.__name__ = "ollama"
            pool["ollama"] = _ollama

        if self._settings.openai_api_key:
            async def _openai() -> str:
                return await self._call_openai_compatible(
                    api_key=self._settings.openai_api_key,
                    base_url="https://api.openai.com/v1",
                    model=self._settings.openai_model,
                    system_prompt=system_prompt,
                    user_content=user_content,
                )
            _openai.__name__ = "openai"
            pool["openai"] = _openai

        if self._settings.anthropic_api_key:
            async def _anthropic() -> str:
                return await self._call_anthropic(system_prompt, user_content)
            _anthropic.__name__ = "anthropic"
            pool["anthropic"] = _anthropic

        # Pinned mode — return ONLY the chosen provider so A/B results are clean.
        if selector != "auto":
            if selector in pool:
                logger.debug("llm_backend_pinned", backend=selector)
                return [pool[selector]]
            logger.warning(
                "llm_backend_not_available",
                requested=selector,
                reason="key not set or provider disabled",
            )
            return []

        # Auto mode — return all available backends in priority order.
        priority = ["grok", "cerebras", "ollama", "openai", "anthropic"]
        return [pool[name] for name in priority if name in pool]

    # ── Per-provider HTTP calls ───────────────────────────────────────────────

    async def _call_openai_compatible(
        self,
        api_key: str,
        base_url: str,
        model: str,
        system_prompt: str,
        user_content: str,
    ) -> str:
        """
        Single helper covering Grok, Cerebras and OpenAI.

        They all expose `/v1/chat/completions` with identical request/response
        schemas, so the only thing that differs is `api_key` + `base_url`.
        """
        from openai import AsyncOpenAI  # lazy import — saves ~150ms on startup

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        completion = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            max_tokens=512,
            temperature=0.4,   # low temp → deterministic, shell-like output
        )
        return completion.choices[0].message.content or _FALLBACK_RESPONSE

    async def _call_ollama(self, system_prompt: str, user_content: str) -> str:
        """Local Ollama HTTP API — only used when OLLAMA_ENABLED=true."""
        payload = {
            "model": self._settings.ollama_model,
            "system": system_prompt,
            "prompt": user_content,
            "stream": False,
            "options": {"temperature": 0.4, "num_predict": 512},
        }
        resp = await self._http.post(
            f"{self._settings.ollama_url}/api/generate",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data.get("response", "")).strip()

    async def _call_anthropic(self, system_prompt: str, user_content: str) -> str:
        """Anthropic uses its own SDK — not OpenAI-compatible."""
        import anthropic  # lazy import

        client = anthropic.AsyncAnthropic(api_key=self._settings.anthropic_api_key)
        message = await client.messages.create(
            model=self._settings.anthropic_model,
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        return message.content[0].text if message.content else _FALLBACK_RESPONSE

    async def close(self) -> None:
        """Called from main.py on shutdown to release the HTTP pool."""
        await self._http.aclose()
