from __future__ import annotations

import asyncio
import json
import socket
import struct

from redis.asyncio import Redis

from app.core.logging import get_logger

logger = get_logger(__name__)

_BLOCKLIST_KEY = "mesh:blocklist"
_BLOCKLIST_TTL = 3600 * 6  # 6 hours


class MeshListener:
    """
    Listens for blocklist broadcasts from peer honeypot nodes and merges them
    into the shared Redis set `mesh:blocklist`.
    """

    def __init__(self, group: str, port: int, redis: Redis) -> None:
        self._group = group
        self._port = port
        self._redis = redis

    async def start(self) -> None:
        logger.info("mesh_listener_starting", group=self._group, port=self._port)
        loop = asyncio.get_running_loop()
        sock = self._create_socket()
        try:
            while True:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
                await self._handle_message(data, addr)
        finally:
            sock.close()

    async def _handle_message(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = json.loads(data.decode())
            node_id = msg.get("node_id", "unknown")
            blocked_ips: list[str] = msg.get("blocked_ips", [])

            if not isinstance(blocked_ips, list):
                return

            if blocked_ips:
                await self._redis.sadd(_BLOCKLIST_KEY, *blocked_ips)
                await self._redis.expire(_BLOCKLIST_KEY, _BLOCKLIST_TTL)
                logger.info(
                    "mesh_received_blocklist",
                    from_node=node_id,
                    from_addr=addr[0],
                    ip_count=len(blocked_ips),
                )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.debug("mesh_invalid_message", reason=str(exc))

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self._port))
        # Join multicast group
        mreq = struct.pack("4sL", socket.inet_aton(self._group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(30)
        return sock
