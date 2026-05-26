"""
Session data models.

These are the core Pydantic objects that flow through the entire system:
  * `Session`          — one per attacker connection (SSH or HTTP).
  * `SessionEvent`     — a single recorded action (command, login, etc.).
  * `CapturedCredential` — credentials harvested from an auth attempt.
  * `AttackPhase`      — the kill-chain stage the attacker is currently in.

Pydantic gives us free JSON (de)serialization, which the SessionManager uses
to persist sessions to Redis as JSON strings.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class AttackPhase(str, Enum):
    """
    Stages of an attack, ordered by severity.

    Phase only ever *escalates* (never downgrades) so that a single recon
    command after an exploit attempt doesn't make the threat look less severe.
    """

    RECON = "RECON"
    BRUTE_FORCE = "BRUTE_FORCE"
    EXPLOITATION = "EXPLOITATION"
    PERSISTENCE = "PERSISTENCE"

    @property
    def severity(self) -> int:
        """Numeric severity used by both the CEF formatter and `escalate()`."""
        return {
            AttackPhase.RECON: 3,
            AttackPhase.BRUTE_FORCE: 6,
            AttackPhase.EXPLOITATION: 8,
            AttackPhase.PERSISTENCE: 9,
        }[self]

    def escalate(self, new_phase: "AttackPhase") -> "AttackPhase":
        """Return whichever phase has higher severity. Phase never downgrades."""
        return new_phase if new_phase.severity > self.severity else self


class SessionEvent(BaseModel):
    """A single thing the attacker did — a command, a login, a probe, etc."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str                       # e.g. "command", "http_login_attempt"
    payload: str                          # the raw command/data
    phase: AttackPhase                    # phase at the moment this happened
    extra: dict[str, str] = Field(default_factory=dict)


class CapturedCredential(BaseModel):
    """A username/password pair we lured out of the attacker."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    username: str
    password: str
    service: str                          # "ssh" or "http"
    method: str                           # "password_auth" or "form_submit"


class Session(BaseModel):
    """
    One attacker connection. Lives in Redis (24h TTL) under `session:{id}`.

    The same model is used for both SSH and HTTP attackers; `service` tells
    us which honeypot it came from.
    """

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attacker_ip: str
    attacker_port: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Current working directory in the virtual filesystem (SSH only).
    current_dir: str = "/home/admin"

    # Highest threat phase seen so far. Updated by ThreatClassifier on each command.
    phase: AttackPhase = AttackPhase.RECON

    command_history: list[str] = Field(default_factory=list)
    captured_credentials: list[CapturedCredential] = Field(default_factory=list)
    events: list[SessionEvent] = Field(default_factory=list)

    service: str = "ssh"                  # "ssh" or "http"
    username: str = "admin"               # username the attacker logged in as
    user_agent: str = ""                  # HTTP only
