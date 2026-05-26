from __future__ import annotations

import asyncio
import json
import socket
import struct
import uuid
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.session.manager import SessionManager

logger = get_logger(__name__)

_NODE_ID = str(uuid.uuid4())[:8]


class MeshBroadcaster:
    """
    Broadcasts the local blocklist to all honeypot nodes on the multicast group.
    Sends a JSON payload every 60 seconds: {"node_id": ..., "blocked_ips": [...], "timestamp": ...}
    """

    def __init__(self, group: str, port: int, session_mgr: SessionManager) -> None:
        self._group = group
        self._port = port
        self._session_mgr = session_mgr

    async def start(self) -> None:
        logger.info("mesh_broadcaster_starting", group=self._group, port=self._port)
        while True:
            try:
                await self._broadcast()
            except Exception as exc:
                logger.error("mesh_broadcast_error", reason=str(exc))
            await asyncio.sleep(60)

    async def _broadcast(self) -> None:
        sessions = await self._session_mgr.list_active()
        blocked_ips = list({s.attacker_ip for s in sessions})

        payload = json.dumps({
            "node_id": _NODE_ID,
            "blocked_ips": blocked_ips,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._send_udp, payload)
        logger.debug("mesh_broadcast_sent", ip_count=len(blocked_ips))

    def _send_udp(self, payload: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            sock.sendto(payload, (self._group, self._port))
        finally:
            sock.close()
