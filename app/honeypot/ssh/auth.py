"""
SSH authentication handler.

Behaviour: ALWAYS accept the login, but only after a 200–800 ms delay.
The delay mimics the time a real OpenSSH server spends doing bcrypt(),
so attackers can't fingerprint us by measuring "no-CPU instant rejects".

Accepting every login is intentional — once inside, the attacker spends
time exploring the fake shell, which is exactly the telemetry we want.
"""
from __future__ import annotations

import random
import threading
from datetime import datetime, timezone

from app.config import settings
from app.core.logging import get_logger
from app.session.models import CapturedCredential

logger = get_logger(__name__)


class SSHAuthHandler:
    """Stateless — same instance is shared by every Paramiko transport."""

    def authenticate(
        self,
        username: str,
        password: str,
        attacker_ip: str,
    ) -> tuple[bool, CapturedCredential]:
        """
        Block for a random bcrypt-like delay, capture the credential,
        and accept the connection.

        Always returns `(True, cred)` — we never reject.
        """
        delay_ms = random.randint(
            settings.ssh_bcrypt_delay_min_ms,
            settings.ssh_bcrypt_delay_max_ms,
        )
        # We're running in a Paramiko worker thread, so a blocking wait is fine
        # (and simpler than asyncio bridging). Event.wait() with no set() acts
        # as an interruptible sleep.
        threading.Event().wait(timeout=delay_ms / 1000.0)

        cred = CapturedCredential(
            timestamp=datetime.now(timezone.utc),
            username=username,
            password=password,
            service="ssh",
            method="password_auth",
        )

        logger.info(
            "ssh_auth_attempt",
            ip=attacker_ip,
            username=username,
            accepted=True,
            delay_ms=delay_ms,
        )

        return True, cred
