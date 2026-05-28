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

# ── Stage 3: test image ─────────────────────────────────────────────────────────
# Extends the app image with the test tooling + the test suite. This stage is
# only built for `make test` (see docker-compose.test.yml) — it is NOT part of
# the production image, so the Raspberry Pi build stays lean.
FROM app AS test

# Install the test tools explicitly. We avoid `pip install -e ".[dev]"` because
# the editable build backend is unreliable in this slim image (the base stage
# works around the same issue with an explicit package list).
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    "fakeredis[aioredis]" \
    respx

COPY tests/ ./tests/

# Default command — unit tests only (fully self-contained, no stack needed).
CMD ["pytest", "tests/unit/", "-v", "--tb=short"]
