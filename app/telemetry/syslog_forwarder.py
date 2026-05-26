from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger(__name__)

_SYSLOG_FACILITY = 16   # local0
_SYSLOG_SEVERITY = 5    # notice
_PRI = (_SYSLOG_FACILITY * 8) + _SYSLOG_SEVERITY  # = 133


class UDPSyslogForwarder:
    """Forwards CEF alerts as RFC 5424 syslog messages over UDP."""

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port

    async def send(self, cef_message: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        hostname = socket.gethostname()
        app_name = "intellihoneypot"
        msg_id = "-"
        structured_data = "-"

        # RFC 5424 syslog message format
        syslog_msg = (
            f"<{_PRI}>1 {timestamp} {hostname} {app_name} - {msg_id} {structured_data} {cef_message}"
        )

        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=(self._host, self._port),
            )
            transport.sendto(syslog_msg.encode("utf-8"))
            transport.close()
        except Exception as exc:
            logger.debug("syslog_send_failed", reason=str(exc))
