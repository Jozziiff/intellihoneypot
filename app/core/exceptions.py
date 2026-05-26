class HoneypotError(Exception):
    """Base exception for all honeypot errors."""


class LLMError(HoneypotError):
    """Raised when all LLM backends fail."""


class LLMTimeoutError(LLMError):
    """Raised when the local Ollama backend times out."""


class LLMCloudError(LLMError):
    """Raised when the cloud API fallback also fails."""


class SessionNotFoundError(HoneypotError):
    """Raised when a session ID cannot be found in Redis."""


class VirtualFSError(HoneypotError):
    """Raised for virtual filesystem path errors."""


class GuardrailViolation(HoneypotError):
    """Raised when prompt injection is detected in attacker input."""


class MeshError(HoneypotError):
    """Raised for P2P mesh communication errors."""
