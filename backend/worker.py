from __future__ import annotations

import asyncio
import logging

from redis.asyncio import Redis

from app.v2.config import settings
from app.v2.db import initialize_database
from app.v2.services import WorkerPipeline


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("siem-worker")


async def _ensure_group(redis_client: Redis, stream: str, group: str) -> None:
    try:
        await redis_client.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def run() -> None:
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    await initialize_database()
    await _ensure_group(redis_client, settings.ingest_stream, settings.ingest_group)
    pipeline = WorkerPipeline(redis_client)
    LOGGER.info("worker started stream=%s group=%s id=%s", settings.ingest_stream, settings.ingest_group, settings.worker_id)
    while True:
        records = await redis_client.xreadgroup(
            groupname=settings.ingest_group,
            consumername=settings.worker_id,
            streams={settings.ingest_stream: ">"},
            count=settings.worker_batch_size,
            block=settings.worker_block_ms,
        )
        if not records:
            continue
        for _, items in records:
            for message_id, payload in items:
                try:
                    await pipeline.process(
                        source_type=payload["source_type"],
                        line=payload["line"],
                        received_at=payload["received_at"],
                    )
                    await redis_client.xack(settings.ingest_stream, settings.ingest_group, message_id)
                except Exception:
                    LOGGER.exception("failed processing message id=%s", message_id)


if __name__ == "__main__":
    asyncio.run(run())

