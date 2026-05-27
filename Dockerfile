# ── Stage 1: base dependencies ────────────────────────────────────────────────
FROM python:3.11-slim AS base

WORKDIR /app

# System packages needed for cryptography (Paramiko) and compiled Redis client
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
# Install production deps only; skip dev/test extras
RUN pip install --no-cache-dir -e "." 2>/dev/null || \
    pip install --no-cache-dir \
        paramiko \
        fastapi \
        "uvicorn[standard]" \
        pydantic-settings \
        "redis[hiredis]" \
        structlog \
        httpx \
        requests \
        bcrypt \
        jinja2 \
        python-multipart \
        pyyaml \
        openai \
        anthropic \
        websockets \
        aiofiles

# ── Stage 2: application image ─────────────────────────────────────────────────
FROM base AS app

WORKDIR /app

COPY app/ ./app/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Pre-generate the SSH host key at build time (overridable via volume mount)
RUN python scripts/generate_host_key.py

# Runtime directories (mounted as volumes in compose)
RUN mkdir -p logs keys

EXPOSE 22 80

# Entrypoint: the asyncio TaskGroup launcher
CMD ["python", "-m", "app.main"]
