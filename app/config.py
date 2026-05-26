from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # LLM backend selector — change this to switch providers for A/B testing.
    # Values: auto | grok | cerebras | openai | anthropic | ollama
    # "auto" tries each configured provider in the order listed above.
    # Any other value uses ONLY that provider (no fallback) so results are clean.
    llm_backend: str = "auto"

    # Grok API (xAI, OpenAI-compatible, free tier)
    grok_api_key: str = ""
    grok_model: str = "grok-3-mini"
    grok_base_url: str = "https://api.x.ai/v1"

    # Cerebras API (OpenAI-compatible, free tier — very fast inference)
    cerebras_api_key: str = ""
    cerebras_model: str = "llama3.1-8b"
    cerebras_base_url: str = "https://api.cerebras.ai/v1"

    # Ollama (optional local LLM — only used when OLLAMA_ENABLED=true)
    ollama_enabled: bool = False
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "phi3:mini"
    ollama_fallback_model: str = "llama3.2:1b"
    ollama_timeout_secs: int = 5

    # Cloud API Fallback
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-haiku-4-5-20251001"

    # Redis
    redis_url: str = "redis://redis:6379/0"
    cache_ttl_seconds: int = 3600

    # Logging & Telemetry
    log_level: str = "INFO"
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514

    # SSH Honeypot
    ssh_port: int = 22
    ssh_bcrypt_delay_min_ms: int = 200
    ssh_bcrypt_delay_max_ms: int = 800
    ssh_max_sessions: int = 30

    # HTTP Honeypot
    http_port: int = 80

    # Admin Dashboard
    dashboard_port: int = 9000
    dashboard_secret_key: str = "change-me-in-production"

    # Multi-Agent Mesh
    mesh_enabled: bool = False
    mesh_multicast_group: str = "239.0.0.1"
    mesh_port: int = 9999

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


# Module-level singleton — import this everywhere
settings = Settings()
