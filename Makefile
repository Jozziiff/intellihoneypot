.PHONY: build up down local-llm restart logs logs-all status shell redis-cli test \
        pull-models cross-build clean help

# ── Configuration ──────────────────────────────────────────────────────────────
COMPOSE        := docker compose
APP_SERVICE    := app
IMAGE_NAME     := intellihoneypot
IMAGE_TAG      := latest
PLATFORMS      := linux/amd64,linux/arm64

# ── Primary Targets ────────────────────────────────────────────────────────────

## build: Build all Docker images
build:
	$(COMPOSE) build

## up: Start all services in the background
up:
	$(COMPOSE) up -d
	@echo ""
	@echo "  Honeypot running:"
	@echo "    SSH  → ssh -p 2222 admin@localhost"
	@echo "    HTTP → http://localhost:8080"
	@echo "    Dashboard → http://localhost:9000"
	@echo ""

## down: Stop and remove all containers (keeps volumes)
down:
	$(COMPOSE) down

## local-llm: Start stack WITH Ollama (requires 4GB+ RAM available to Docker)
local-llm:
	$(COMPOSE) --profile local-llm up -d
	@echo ""
	@echo "  Stack running with Ollama enabled."
	@echo "  Run 'make pull-models' to download phi3:mini if not already cached."
	@echo ""

## restart: Restart the app container (for code changes)
restart:
	$(COMPOSE) restart $(APP_SERVICE)

## status: Show container status and health
status:
	$(COMPOSE) ps

## logs: Tail app container logs
logs:
	$(COMPOSE) logs -f $(APP_SERVICE)

## logs-all: Tail all container logs
logs-all:
	$(COMPOSE) logs -f

# ── Development ────────────────────────────────────────────────────────────────

## shell: Open a bash shell inside the app container
shell:
	$(COMPOSE) exec $(APP_SERVICE) bash

## redis-cli: Open a Redis CLI session
redis-cli:
	$(COMPOSE) exec redis redis-cli

## test: Run the full pytest suite inside the container
test:
	$(COMPOSE) run --rm $(APP_SERVICE) pytest tests/ -v --tb=short

## test-unit: Run only unit tests (no Docker/network required)
test-unit:
	$(COMPOSE) run --rm $(APP_SERVICE) pytest tests/unit/ -v

## test-integration: Run integration tests
test-integration:
	$(COMPOSE) run --rm $(APP_SERVICE) pytest tests/integration/ -v

## lint: Run ruff linter
lint:
	$(COMPOSE) run --rm $(APP_SERVICE) ruff check app/ tests/

## typecheck: Run mypy type checker
typecheck:
	$(COMPOSE) run --rm $(APP_SERVICE) mypy app/

# ── LLM Models ────────────────────────────────────────────────────────────────

## pull-models: Pull required LLM models into Ollama (run once after 'make up')
pull-models:
	@echo "Pulling phi3:mini (~2.3GB)..."
	$(COMPOSE) exec ollama ollama pull phi3:mini
	@echo "Pulling llama3.2:1b (~1.3GB) as fallback..."
	$(COMPOSE) exec ollama ollama pull llama3.2:1b
	@echo "Models ready."

## list-models: List available Ollama models
list-models:
	$(COMPOSE) exec ollama ollama list

# ── Cross-Compilation (Raspberry Pi ARM64) ─────────────────────────────────────

## cross-build: Build multi-arch image for linux/amd64 + linux/arm64
cross-build:
	@echo "Building multi-architecture image for $(PLATFORMS)..."
	@echo "Make sure 'docker buildx create --use' has been run once."
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_NAME):$(IMAGE_TAG) \
		--push \
		.
	@echo "Multi-arch image pushed: $(IMAGE_NAME):$(IMAGE_TAG)"

## buildx-setup: One-time setup for cross-compilation builder
buildx-setup:
	docker buildx create --name honeypot-builder --use --bootstrap
	docker buildx inspect --bootstrap

# ── Cleanup ───────────────────────────────────────────────────────────────────

## clean: Stop containers, remove volumes, clean up
clean:
	$(COMPOSE) down -v
	@echo "All containers and volumes removed."

## clean-logs: Clear the event log file
clean-logs:
	@truncate -s 0 logs/events.jsonl 2>/dev/null || true
	@echo "Logs cleared."

# ── Seed / Utilities ──────────────────────────────────────────────────────────

## seed-cache: Pre-warm the LLM Redis cache with common commands
seed-cache:
	$(COMPOSE) run --rm $(APP_SERVICE) python scripts/seed_redis.py

## gen-key: Regenerate the SSH host key
gen-key:
	$(COMPOSE) run --rm $(APP_SERVICE) python scripts/generate_host_key.py
	@echo "New SSH host key generated in keys/"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo ""
	@echo "IntelliHoneypot — Available Makefile targets:"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /'
	@echo ""
