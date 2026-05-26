"""
Session persistence — stores `Session` objects in Redis.

Why Redis (and not e.g. SQLite)?
  * Atomic operations on hashes/sets are perfect for high-churn ephemeral data.
  * 24 h TTL gives us automatic cleanup of dead sessions.
  * The dashboard and the honeypot containers can share state without IPC.

Layout in Redis:
  * `session:{uuid}`     — one JSON string per session (TTL 24 h).
  * `sessions:active`    — sorted set of session IDs scored by last-seen
                        timestamp. Lets the dashboard list "what's live".
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from redis.asyncio import Redis

from app.core.exceptions import SessionNotFoundError
from app.core.logging import get_logger
from app.session.models import CapturedCredential, Session, SessionEvent

logger = get_logger(__name__)

_SESSION_PREFIX = "session:"
_ACTIVE_ZSET = "sessions:active"
_TTL_SECONDS = 3600 * 24  # 24 hours — enough for forensic review after attack


class SessionManager:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    # ── Key helpers ───────────────────────────────────────────────────────────

    def _key(self, session_id: str) -> str:
        return f"{_SESSION_PREFIX}{session_id}"

    # ── CRUD ──────────────────────────────────────────────────────────────────

    async def create(
        self, attacker_ip: str, service: str, attacker_port: int = 0
    ) -> Session:
        session = Session(
            attacker_ip=attacker_ip, attacker_port=attacker_port, service=service
        )
        await self._persist(session)
        await self._redis.zadd(_ACTIVE_ZSET, {session.session_id: time.time()})
        logger.info(
            "session_created",
            session_id=session.session_id,
            ip=attacker_ip,
            service=service,
        )
        return session

    async def get(self, session_id: str) -> Session:
        raw = await self._redis.get(self._key(session_id))
        if raw is None:
            raise SessionNotFoundError(session_id)
        return Session.model_validate_json(raw)

    async def update(self, session: Session) -> None:
        # Refresh `last_seen` on every write so the active-set score stays current.
        session.last_seen = datetime.now(timezone.utc)
        await self._persist(session)
        await self._redis.zadd(_ACTIVE_ZSET, {session.session_id: time.time()})

    async def delete(self, session_id: str) -> None:
        await self._redis.delete(self._key(session_id))
        await self._redis.zrem(_ACTIVE_ZSET, session_id)
        logger.info("session_deleted", session_id=session_id)

    async def list_active(self) -> list[Session]:
        """Return every session known to the active set. Prunes stale entries."""
        session_ids = await self._redis.zrange(_ACTIVE_ZSET, 0, -1)
        sessions: list[Session] = []
        for sid in session_ids:
            try:
                sessions.append(await self.get(sid))
            except SessionNotFoundError:
                # Sorted set still references a session whose JSON has expired;
                # remove the dangling ID so future calls are clean.
                await self._redis.zrem(_ACTIVE_ZSET, sid)
        return sessions

    # ── Event/credential helpers ──────────────────────────────────────────────

    async def append_event(self, session_id: str, event: SessionEvent) -> None:
        """
        Re-read the session from Redis, append an event, and write it back.

        NOTE: This is *not* safe to call concurrently with in-memory mutations
        of the same Session — the SSH shell handler bypasses this method and
        mutates its in-memory copy directly to avoid race conditions.
        """
        session = await self.get(session_id)
        session.events.append(event)
        # Cap history so a long-lived session can't grow unboundedly.
        if len(session.command_history) > 100:
            session.command_history = session.command_history[-100:]
        await self.update(session)

    async def capture_credential(
        self, session_id: str, cred: CapturedCredential
    ) -> None:
        session = await self.get(session_id)
        session.captured_credentials.append(cred)
        logger.warning(
            "credential_captured",
            session_id=session_id,
            ip=session.attacker_ip,
            username=cred.username,
            service=cred.service,
        )
        await self.update(session)

    async def all_credentials(self) -> list[dict[str, object]]:
        """Flatten every captured credential across every active session."""
        sessions = await self.list_active()
        result: list[dict[str, object]] = []
        for s in sessions:
            for c in s.captured_credentials:
                # `mode="json"` makes datetimes serialize as ISO 8601 strings —
                # without it, FastAPI would crash trying to JSON-encode datetime.
                result.append(
                    {
                        "session_id": s.session_id,
                        "attacker_ip": s.attacker_ip,
                        **c.model_dump(mode="json"),
                    }
                )
        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _persist(self, session: Session) -> None:
        await self._redis.setex(
            self._key(session.session_id),
            _TTL_SECONDS,
            session.model_dump_json(),
        )
