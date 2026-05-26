# AI Developer Instructions: LLM-Based Intelligent Honeypot (PFA Project)

## 1. Project Overview & Context
You are tasked with developing a production-ready, "plug-and-work" Intelligent Honeypot based on an architecture integrating Large Language Models (LLMs). The system will simulate realistic network services (SSH and HTTP) to deceive attackers, dynamically generate believable responses, analyze behaviors, and forward actionable telemetry.

**Hardware & Deployment Constraint:** The final deployment target is a Raspberry Pi OS Lite (64-bit), but development is currently strictly containerized. You must use Docker and Docker Compose to build this environment and use resource limits (e.g., RAM/CPU capping) to simulate the Raspberry Pi's constraints. The codebase must remain 100% portable for a direct hardware deployment later using multi-architecture build tools like `docker buildx`.

## 2. Global Architecture & Tech Stack
* **Language:** Python 3.11+.
* **Infrastructure:** Docker & Docker Compose (used to simulate edge hardware).
* **Services Emulation:** `Paramiko` for SSH, `Flask` or `FastAPI` for HTTP.
* **LLM Backend:** Local `Ollama` container running `phi3:mini` (with `llama3.2:1b` fallback) and a Cloud API failover.
* **State & Caching:** `redis` (containerized).
* **Logging & Telemetry:** `structlog` for JSON output, forwarding CEF alerts.

## 3. Step-by-Step Implementation Plan

### Phase 0: Containerized Infrastructure & Shared State
* **Docker Compose Setup:** Create a `docker-compose.yml` deploying the app, Redis, and Ollama. Limit the app container's resources to simulate the Pi (e.g., `cpus: '0.5'`, `mem_limit: 512m`). Use lightweight base images (`python:3.11-slim`). Provide a `Makefile` or shell scripts utilizing `docker buildx` to ensure smooth `linux/arm64` cross-compilation later.
* **Virtual Filesystem (`config/fake_fs.json`):** Create a realistic Linux directory tree containing `/etc/passwd` (15 fake users), `/home/admin/.ssh/id_rsa`, `/var/www/html/config.php` (fake MySQL credentials), and `/var/log/auth.log`.
* **Session Manager:** Implement a centralized state-tracking mechanism per attacker IP, logging the virtual current directory, session history, and active attack stage.

### Phase 1: Service Emulation (The "Galah" Inspiration)
* **HTTP Honeypot (Port 8080 mapped to 80):**
    * *Inspiration from DEF CON "Decrypting Galah":* Do not just emulate a generic website. Emulate a high-value enterprise portal—specifically, build a fake VPN login interface (like a Palo Alto GlobalProtect or Cisco AnyConnect web portal) or a corporate SSO login. This attracts higher-quality, sophisticated credential harvesting attempts.
    * Use realistic headers: `Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`.
    * Route automated scans (Nikto/Dirb) seamlessly without crashing.
* **SSH Honeypot (Port 2222 mapped to 22):** * Use `Paramiko` to intercept raw TCP traffic. Force a `bcrypt` delay (200-800ms) on all auth attempts.
    * Expose a fake interactive shell. Trap standard terminal signals (Ctrl+C, Ctrl+D).
    * Answer static low-level commands (`whoami`, `pwd`, `uname -a`) from local configuration to save LLM compute overhead.

### Phase 2: LLM Orchestration & Defensive Guardrails
* **Caching (`ResponseCache`):** Hash the command/context and store in Redis with a 1-hour TTL. Always check cache before hitting the LLM.
* **LLM Integration:** * Set model temperature to 0.5.
    * Enforce a strict 3-second timeout for the local Ollama container. If it fails or lags, fall back to a cloud API (OpenAI/Claude via `.env`).
* **Personas & Protections:** * `persona_ssh.yaml`: Emulate an Ubuntu 20.04 server terminal.
    * Implement Regex anti-prompt injection (e.g., truncate at 500 characters, block "ignore previous instructions").
    * Simulate human typing delays over SSH (flushing output at 15-40 chars/sec) to defeat AI detection timing analysis.

### Phase 3: Telemetry, Management Web UI & Multi-Agent
* **Structured Logging & Classifier:** Log append-only JSON to `logs/events.jsonl`. Classify attacks into RECON, BRUTE_FORCE, EXPLOITATION, and PERSISTENCE. Format alerts into CEF and forward via UDP syslog.
* **Admin Web UI Dashboard (Port 9000):** Build a dedicated Management Dashboard using Flask/FastAPI backend and Jinja2/Chart.js frontend. It must display:
    * Real-time active attacker sessions.
    * Threat phase charts.
    * A specific view for captured payloads/credentials harvested from the VPN HTTP honeypot.
* **Multi-Agent Mesh:** Implement a P2P broadcasting logic allowing honeypot nodes to share malicious IP blocklists across the network.

## 4. Operational & Developer Workflow Requirements
* **Write Code Step-by-Step:** Do not output the entire monolithic architecture at once. Begin by defining the `docker-compose.yml` and configs, wait for my validation, and then proceed phase by phase.
* **No Placeholders:** Every core loop, error handler, and configuration file must be fully functional. It must run flawlessly within the Docker constraints today so that it works seamlessly on the physical Raspberry Pi tomorrow. Document every file structure and command extensively.