from redis.asyncio import Redis, ConnectionPool


_pool: ConnectionPool | None = None


async def create_redis_pool(url: str) -> Redis:
    global _pool
    _pool = ConnectionPool.from_url(
        url,
        max_connections=20,
        decode_responses=True,
    )
    client: Redis = Redis(connection_pool=_pool)
    # Verify connectivity immediately
    await client.ping()
    return client


async def close_redis_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
