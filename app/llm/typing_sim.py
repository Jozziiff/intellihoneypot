"""
Human-typing simulator for SSH output.

Why this exists: LLM responses arrive over the network in one big blob.
If we dumped that blob instantly, an attacker's automated tooling could
fingerprint us by latency alone ("real shells don't reply 800 chars in
4 ms"). Streaming the output at a realistic 15–40 chars/sec defeats that
timing-based detection.

NOTE: This module is currently NOT wired into the shell — FakeShell
sends output in one chunk for now. Hook it back into FakeShell._handle_line
when you want typing-speed realism.
"""
from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import paramiko


class TypingSimulator:
    """Streams text to a Paramiko SSH channel at human-like typing speeds."""

    MIN_CHARS_PER_SEC: int = 15
    MAX_CHARS_PER_SEC: int = 40

    async def stream_to_channel(self, channel: "paramiko.Channel", text: str) -> None:
        """Send `text` in small chunks with realistic inter-chunk delays."""
        rate = random.uniform(self.MIN_CHARS_PER_SEC, self.MAX_CHARS_PER_SEC)
        # Roughly 100 ms per chunk — fast enough to feel snappy, slow enough
        # to read like real typing.
        chunk_size = max(1, int(rate / 10))
        delay = 1.0 / (rate / chunk_size)

        for i in range(0, len(text), chunk_size):
            chunk = text[i : i + chunk_size]
            try:
                channel.sendall(chunk.encode("utf-8", errors="replace"))
            except OSError:
                # Attacker dropped the connection mid-stream — stop cleanly.
                return
            # ±10 % jitter so the cadence isn't perfectly periodic.
            await asyncio.sleep(delay + random.uniform(-delay * 0.1, delay * 0.1))
