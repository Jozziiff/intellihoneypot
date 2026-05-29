<div align="center">

# 🍯 IntelliHoneypot

**An LLM-powered adaptive honeypot that generates realistic, session-aware responses in real time**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docs.docker.com/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)](https://redis.io/)
[![Paramiko](https://img.shields.io/badge/Paramiko-SSH-darkblue?style=flat-square)](https://www.paramiko.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey?style=flat-square&logo=raspberry-pi)](https://www.raspberrypi.com/)
[![PFA](https://img.shields.io/badge/INSAT-RT4%20PFA%202026-blue?style=flat-square)](https://insat.rnu.tn/)

<br/>

*Traditional honeypots are fingerprint-able in seconds. IntelliHoneypot isn't.*

<br/>

</div>

---

## What Makes This Different

Most honeypots serve canned responses from a static database. Experienced attackers and automated tools detect them trivially — command latency is machine-regular, output is identical across deployments, and any unusual command returns the same generic error.

**IntelliHoneypot replaces the static response database with a live LLM.** Every unknown command is answered with a contextually coherent response generated against the session's full history. The system knows what directory the attacker navigated to, what files they read, what user they authenticated as — and the LLM response reflects all of that.

```
Attacker types:  find / -name "*.conf" -perm -4000 2>/dev/null
   ↓ not in static table → LLMOrchestrator
   ↓ check Redis cache (SHA-256 keyed) → miss
   ↓ build prompt: persona + session history + guardrails
   ↓ call Grok API (or Cerebras / OpenAI / Anthropic / Ollama)
   ↓ cache response → return
Attacker sees:   /etc/mysql/my.cnf   /etc/nginx/nginx.conf   /usr/local/etc/php.ini
```

On cache hit the response is served in **< 1 ms**. An estimated 90%+ of attacker commands are repeated reconnaissance patterns — the cache absorbs them all after the first session.

---

## Feature Overview

| Capability | Detail |
|---|---|
| **Interactive SSH Shell** | Full `bash`-like shell via Paramiko. Handles Ctrl+C, Ctrl+D, backspace, ANSI sequences |
| **Static command dispatch** | 15 built-in handlers (`ls`, `cat`, `cd`, `whoami`, `uname`, …) answered locally in 0 ms |
| **LLM response generation** | Unknown commands go to a 5-provider chain with automatic fallback |
| **Redis LLM cache** | SHA-256 keyed, 1-hour TTL — eliminates redundant API calls |
| **HTTP VPN portal** | Palo Alto GlobalProtect clone — attracts sophisticated credential-stuffing actors |
| **Credential harvesting** | SSH auth attempts + HTTP form submissions captured with full metadata |
| **4-phase classifier** | `RECON → BRUTE_FORCE → EXPLOITATION → PERSISTENCE` — phase never downgrades |
| **Prompt injection guard** | 10 regex patterns, 500-char limit, auto-escalates session phase on detection |
| **Human typing simulation** | 15–40 chars/sec with ±10% jitter — defeats AI-timing fingerprinting |
| **Admin dashboard** | Real-time Chart.js charts, session table, credential log — auto-refreshes every 10 s |
| **Structured telemetry** | Append-only `events.jsonl` + ArcSight CEF:0 alerts + UDP syslog forwarding |
| **Multi-agent mesh** | UDP multicast blocklist sharing between honeypot nodes |
| **Raspberry Pi ready** | Resource caps match Pi 4B constraints; multi-arch build (`amd64` + `arm64`) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET / NETWORK                          │
└──────────────┬──────────────────────────────────┬───────────────────┘
               │ :2222  (→ 22 inside container)    │ :8080  (→ 80)
               ▼                                   ▼
┌──────────────────────────┐         ┌─────────────────────────────┐
│      SSH Honeypot        │         │      HTTP Honeypot           │
│  Paramiko ServerInterface│         │   FastAPI + Jinja2           │
│                          │         │                              │
│  • bcrypt timing delay   │         │  • GlobalProtect VPN portal  │
│  • Interactive FakeShell │         │  • Credential capture        │
│  • Command dispatch      │         │  • Nikto/Dirb sink           │
│  • LLM streaming         │         │  • Apache/PHP fake headers   │
└──────────┬───────────────┘         └────────────┬────────────────┘
           │                                       │
           └──────────────┬────────────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │        SessionManager        │
           │  Redis-backed state per IP   │
           │  • Session CRUD              │
           │  • Credential aggregation    │
           │  • Sorted Set active index   │
           └──────────┬───────────────────┘
                      │
       ┌──────────────┼───────────────┐
       ▼              ▼               ▼
┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐
│LLMOrchestrat│ │ThreatClassifi│ │        Redis          │
│             │ │er            │ │                       │
│ 1. Grok     │ │              │ │ session:{uuid}  JSON  │
│ 2. Cerebras │ │ RECON        │ │ sessions:active ZSET  │
│ 3. Ollama * │ │   ↓          │ │ llm:cache:{sha256}    │
│ 4. OpenAI   │ │ BRUTE_FORCE  │ │ mesh:blocklist SET    │
│ 5. Anthropic│ │   ↓          │ │                       │
│ 6. Fallback │ │ EXPLOITATION │ │ AOF everysec, 64 MB   │
└─────────────┘ │   ↓          │ └──────────────────────┘
                │ PERSISTENCE  │
                └──────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │       Telemetry Pipeline     │
       │  events.jsonl  CEF:0  Syslog │
       └──────────────┬───────────────┘
                      ▼
       ┌──────────────────────────────┐
       │   Admin Dashboard  :9000     │
       │  Chart.js + Bootstrap 5      │
       │  /api/sessions  /api/threats │
       │  /api/credentials            │
       └──────────────────────────────┘

* Ollama only starts with: docker compose --profile local-llm up
```

---

## Quick Start

### Prerequisites

- Docker Desktop (or Docker Engine + Compose v2)
- A free API key from [console.x.ai](https://console.x.ai) (Grok) **or** [cloud.cerebras.ai](https://cloud.cerebras.ai) (Cerebras) — both have generous free tiers

### 1. Clone and Configure

```bash
git clone <YOUR_REPO_URL>
cd RT4-PFA

cp .env.example .env
```

Open `.env` and set at least one LLM key:

```env
# Primary — pick one (or both, the system falls through automatically)
GROK_API_KEY=xai-...
CEREBRAS_API_KEY=csk-...
```

### 2. Build and Start

```bash
make build    # docker compose build
make up       # docker compose up -d
make status   # docker compose ps
```

Three containers start: `intellihoneypot-app`, `intellihoneypot-dashboard`, `intellihoneypot-redis`.

### 3. Test It

```bash
# SSH honeypot
ssh -p 2222 admin@localhost
# Any password is accepted after a realistic bcrypt delay
# Try: whoami  |  cat /etc/passwd  |  find / -name "*.conf"

# HTTP honeypot
open http://localhost:8080
# Redirects to the GlobalProtect VPN portal — try submitting fake credentials

# Admin dashboard
open http://localhost:9000
# Charts, session table, and captured credentials appear live
```

### 4. Watch the Logs

```bash
make logs                           # live structured JSON from app container
tail -f logs/events.jsonl | jq .    # forensic event log (requires jq)
```

---

## **WhatsApp Alerting (n8n webhook)**

- **What:** Alerts generated by `EventLogger` are POSTed to an n8n webhook which in turn forwards a WhatsApp template message. This allows immediate operator notification for honeypot activity.
- **Hook URL:** Set `N8N_WEBHOOK_URL` in your `.env` to the n8n webhook endpoint (e.g. `https://intellihon.app.n8n.cloud/webhook-test/<id>`).
- **Payload:** The app sends JSON with the exact fields your n8n workflow expects:

```json
{
  "event_type": "login_failure",
  "ip": "192.168.1.105",
  "timestamp": "2026-05-27 11:31:00",
  "severity": "HIGH",
  "details": "Brute force attack detected - 5 failed login attempts"
}
```

- **Which events trigger:** page views on the HTTP honeypot (`http_page_view`), credential submissions (`http_login_attempt`), SSH authentication failures (`login_failure`) and classified HIGH/interesting events. Every HTTP page view and login submit is routed through `EventLogger` and will attempt to send a webhook (deduped per IP).
- **Deduplication:** To avoid spamming, alerts are deduplicated per source IP for a 60s window by default.
- **n8n Workflow:** Your workflow should accept the incoming webhook and forward the fields into a WhatsApp "Send template" node. A minimal flow is: `Webhook (POST)` → `Send template (WhatsApp)` (see attached screenshot for an example).
- **Testing:**
  - From host or container, replicate your `curl` test:

```bash
curl -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"login_failure","ip":"192.168.1.105","timestamp":"2026-05-27 11:31:00","severity":"HIGH","details":"Brute force attack detected - 5 failed login attempts"}'
```

  - Or exercise the honeypot: open `http://localhost:8080/` and submit credentials; the HTTP page view and submit both flow through `EventLogger` and should trigger the webhook.
- **Troubleshooting:**
  - Tail the app logs to confirm delivery and response from n8n:

```powershell
docker logs -f intellihoneypot-app
```

  - Look for lines like `n8n webhook sent status=200 body=...` or `n8n webhook request failed: ...`.

## All Make Targets

```
make build        Build Docker images
make up           Start all services (detached)
make down         Stop and remove containers
make restart      down + up
make status       Show container health
make logs         Follow app container logs
make shell        bash inside the app container
make test         Run pytest suite inside Docker
make gen-key      Regenerate SSH host key
make flush-cache  Wipe Redis LLM cache (keeps sessions)
make flush-redis  Wipe all Redis data (destructive)
make local-llm    Start stack WITH Ollama (needs 4 GB+ RAM)
make cross-build  Build linux/amd64 + linux/arm64 manifest
```

---

## Configuration Reference

All settings live in `.env` (copied from `.env.example`). Every variable maps directly to a field in `app/config.py`.

### LLM Backends

```env
# Pin a single backend for A/B testing (auto = try all in priority order)
LLM_BACKEND=auto          # auto | grok | cerebras | openai | anthropic | ollama

# Grok (xAI) — free tier, OpenAI-compatible
GROK_API_KEY=xai-...
GROK_MODEL=grok-3-mini
GROK_BASE_URL=https://api.x.ai/v1

# Cerebras — free tier, fastest inference
CEREBRAS_API_KEY=csk-...
CEREBRAS_MODEL=llama3.1-8b
CEREBRAS_BASE_URL=https://api.cerebras.ai/v1

# Ollama (local) — start with: make local-llm
OLLAMA_ENABLED=false
OLLAMA_URL=http://ollama:11434
OLLAMA_MODEL=phi3:mini

# Cloud fallbacks
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

### SSH Honeypot Tuning

```env
SSH_BCRYPT_DELAY_MIN_MS=200   # Min auth delay (ms) — simulates bcrypt cost
SSH_BCRYPT_DELAY_MAX_MS=800   # Max auth delay (ms)
SSH_MAX_SESSIONS=30           # Hard limit on concurrent shells
```

### Mesh (Multi-node IP sharing)

```env
MESH_ENABLED=false
MESH_MULTICAST_GROUP=239.0.0.1
MESH_PORT=9999
```

### Syslog Forwarding (SIEM integration)

```env
SYSLOG_HOST=127.0.0.1   # Replace with your SIEM's IP
SYSLOG_PORT=514
```

---

## Project Structure

```
RT4-PFA/
│
├── app/                          Main application package
│   ├── main.py                   Entry point — starts SSH + HTTP + Dashboard concurrently
│   ├── config.py                 All settings (pydantic-settings, loads from .env)
│   │
│   ├── core/                     Cross-cutting infrastructure
│   │   ├── logging.py            structlog JSON configuration
│   │   ├── redis_client.py       Redis connection pool factory
│   │   └── exceptions.py         Custom exception hierarchy
│   │
│   ├── session/                  Attacker session state
│   │   ├── models.py             Pydantic: Session, AttackPhase, SessionEvent, CapturedCredential
│   │   ├── manager.py            SessionManager — CRUD on Redis hashes + sorted set
│   │   └── virtual_fs.py         VirtualFilesystem — loads and queries fake_fs.json
│   │
│   ├── honeypot/
│   │   ├── ssh/                  SSH honeypot stack
│   │   │   ├── transport.py      TCP accept loop + asyncio↔Paramiko bridge
│   │   │   ├── server.py         HoneypotSSHServer (Paramiko ServerInterface)
│   │   │   ├── shell.py          FakeShell — interactive command loop
│   │   │   └── auth.py           SSHAuthHandler — bcrypt delay + credential capture
│   │   │
│   │   └── http/                 HTTP honeypot stack
│   │       ├── app.py            FastAPI app factory
│   │       ├── middleware.py     Header injection + request logging
│   │       ├── routes/
│   │       │   ├── vpn_portal.py GlobalProtect portal routes + credential capture
│   │       │   ├── scanner_sink.py Catch-all 404 (Nikto / Dirb safe)
│   │       │   └── api_mock.py   /api/* plausible JSON responses
│   │       └── templates/        login.html, base.html, error.html
│   │
│   ├── llm/                      LLM orchestration layer
│   │   ├── orchestrator.py       Backend chain + fallback logic
│   │   ├── cache.py              ResponseCache — Redis SHA-256 keyed
│   │   ├── guardrails.py         InputGuardrail — injection detection + truncation
│   │   ├── prompt_builder.py     PromptBuilder — persona + session history injection
│   │   └── typing_sim.py         TypingSimulator — 15–40 chars/sec human-speed streaming
│   │
│   ├── telemetry/                Observability and alerting
│   │   ├── classifier.py         ThreatClassifier — 4-phase regex engine
│   │   ├── event_logger.py       EventLogger — append-only events.jsonl
│   │   ├── cef_formatter.py      CEFFormatter — ArcSight CEF:0 strings
│   │   └── syslog_forwarder.py   UDPSyslogForwarder — async UDP datagram
│   │
│   ├── dashboard/                Admin web UI
│   │   ├── app.py                FastAPI dashboard app factory (port 9000)
│   │   ├── routes/               /api/sessions, /api/threats, /api/credentials
│   │   └── templates/            index.html, sessions.html, credentials.html, base.html
│   │
│   └── mesh/                     Multi-agent IP sharing
│       ├── broadcaster.py        UDP multicast sender (blocklist → peers)
│       └── listener.py           UDP multicast receiver (peers → Redis SET)
│
├── config/                       Static configuration data (read-only in containers)
│   ├── fake_fs.json              Virtual Linux filesystem tree (dirs, files, permissions)
│   ├── persona_ssh.yaml          Ubuntu 20.04 persona — MOTD, static responses, LLM prompt
│   └── persona_http.yaml         GlobalProtect persona metadata
│
├── tests/
│   ├── conftest.py               fakeredis fixtures, mock LLM
│   ├── unit/                     test_guardrails, test_classifier, test_virtual_fs,
│   │                             test_session_manager, test_response_cache, test_cef_formatter
│   └── integration/              test_ssh_auth, test_http_portal, test_llm_fallback
│
├── scripts/
│   ├── generate_host_key.py      RSA 2048 key generation → keys/host_rsa
│   └── seed_redis.py             Pre-warm LLM cache with common recon commands
│
├── keys/                         SSH host key (git-ignored, Docker volume)
├── logs/                         events.jsonl runtime output (git-ignored, Docker volume)
├── docs/
│   └── TECHNICAL_REPORT.md       Full technical documentation (architecture, design decisions, bug log)
│
├── docker-compose.yml            Production service definitions
├── docker-compose.override.yml   Dev overrides (volume mounts, no resource caps)
├── Dockerfile                    Multi-stage build (python:3.11-slim)
├── Makefile                      All workflow targets
├── pyproject.toml                Dependencies + ruff + mypy + pytest config
└── .env.example                  Environment variable template
```

---

## Customization Guide

### Change the SSH Shell Persona

Edit `config/persona_ssh.yaml`:

```yaml
persona:
  os: "Ubuntu 20.04.6 LTS"
  hostname: "ubuntu-server"      # ← change the hostname
  default_user: "admin"          # ← change the default SSH user

static_responses:
  whoami: "{username}"           # ← override any static command output
  hostname: "ubuntu-server"

llm_system_prompt: |
  You are the bash shell of an Ubuntu 20.04.6 LTS server...
  # ← edit this to change the LLM's personality entirely
```

Restart after changes: `docker compose restart app`

### Add Files to the Fake Filesystem

Edit `config/fake_fs.json`. Each entry is a `file` or a `dir`:

```json
"/etc/my-app/secrets.conf": {
  "type": "file",
  "permissions": "-rw-------",
  "owner": "root", "group": "root", "size": 312,
  "content": "API_KEY=AKIAIOSFODNN7EXAMPLE\nDB_URL=postgres://admin:hunter2@db:5432/prod\n"
}
```

Then add the filename to the parent dir's `children` array:

```json
"/etc/my-app": {
  "type": "dir",
  "permissions": "drwx------",
  "owner": "root", "group": "root", "size": 4096,
  "children": ["secrets.conf"]
}
```

### Switch or Pin the LLM Backend

```env
# In .env:
LLM_BACKEND=cerebras    # only Cerebras — clean A/B testing
LLM_BACKEND=auto        # try all configured providers in priority order
```

Priority order in `auto` mode: **Grok → Cerebras → Ollama → OpenAI → Anthropic → hardcoded fallback.**

### Run with a Local LLM (Ollama)

```bash
make local-llm     # starts stack + Ollama container
make pull-models   # pulls phi3:mini (~2.2 GB)
```

Set in `.env`:

```env
OLLAMA_ENABLED=true
OLLAMA_MODEL=phi3:mini
```

Requires ~4 GB RAM available to Docker beyond the app and Redis footprint.

### Forward Alerts to a SIEM

```env
SYSLOG_HOST=192.168.1.50    # your Splunk / QRadar / Graylog IP
SYSLOG_PORT=514
```

Each event is sent as UDP syslog containing an ArcSight CEF:0 string. In Splunk, use the `syslog` input with `sourcetype=arcsight`.

---

## Running Tests

```bash
make test
# Runs pytest inside the app container against fakeredis fixtures
# No real Redis or LLM required

# Or directly:
docker compose run --rm app pytest tests/ -v --tb=short
```

Unit tests cover: guardrails, threat classifier, virtual filesystem, session manager, response cache, CEF formatter.

---

## Deployment on Raspberry Pi

```bash
# On your development machine — build both architectures
make cross-build
# Pushes linux/amd64 + linux/arm64 manifest to your registry

# On the Raspberry Pi
git clone <YOUR_REPO_URL> && cd RT4-PFA
cp .env.example .env   # add your API keys
docker compose up -d

# Dashboard available at http://<pi-ip>:9000
```

The app container is capped at `cpus: 0.5` and `memory: 512M` — these limits are intentional and match the simulated Pi constraints validated during development.

---

## Dashboard Previews

> *Replace these placeholders with actual screenshots after deployment.*

| Page | What you'll see |
|---|---|
| **Overview** (`/`) | Phase doughnut, top attacker IPs bar chart, SSH/HTTP breakdown, live session table with command counts |
| **Sessions** (`/sessions`) | Per-session detail: IP, service, phase badge, username, command count, current directory, timestamps |
| **Credentials** (`/credentials`) | All captured SSH + HTTP credentials with attacker IP, timestamp, and capture method |

---

## Team

<table>
<tr>

<td align="center" width="300">

<img src="static\jozef.jfif" width="120" height="120" style="border-radius:50%;" alt="Youssef Hamdani"/>

### Youssef Hamdani

**RT4 — INSAT**

Network & Telecommunications Engineering

Honeypot architecture · LLM integration  
SSH emulation · Admin Dashboard

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](github.com/Jozziiff)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/youssef-hamdani2)

</td>

<td align="center" width="300">

<img src="static\ons.jfif" width="120" height="120" style="border-radius:50%;" alt="Ons Souidi"/>

### Ons Souidi

**RT4 — INSAT**

Network & Telecommunications Engineering

HTTP emulation · Telemetry pipeline  
Dashboard Features · Testing · Mutli-agent system extension

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](github.com/onssouidi)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ons-souidi-48a19b24b/)

</td>

</tr>
</table>

**Supervisor:** Kamel Karoui — INSAT  
**Academic Year:** 2025–2026

---

## References

- **Galah** (DEF CON 2023) — LLM-powered HTTP honeypot, direct inspiration for the HTTP persona design
- **MITRE ATT&CK** — The 4-phase classifier maps to TA0043 (Recon), TA0006 (Credential Access), TA0002 (Execution), TA0003 (Persistence)
- **ArcSight CEF:0** — Standard used for SIEM-compatible alert formatting
- **Spitzner, L.** — *Honeypots: Tracking Hackers* (2003)

---

## License

MIT — see [LICENSE](LICENSE).

---

> **Security note:** Deploy IntelliHoneypot in an isolated network segment or behind a firewall controlling inbound access to ports 2222 and 8080. Never commit real credentials. The `.env` file and `keys/` directory are git-ignored by design — keep them that way.
