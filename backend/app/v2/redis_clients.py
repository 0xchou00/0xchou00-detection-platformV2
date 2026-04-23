from __future__ import annotations

from redis.asyncio import Redis

from app.v2.config import settings


def stream_redis() -> Redis:
    return Redis.from_url(settings.stream_redis_url, decode_responses=True)


def pubsub_redis() -> Redis:
    return Redis.from_url(settings.pubsub_redis_url, decode_responses=True)


def state_redis() -> Redis:
    return Redis.from_url(settings.state_redis_url, decode_responses=True)

