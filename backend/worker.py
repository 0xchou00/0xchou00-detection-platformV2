from __future__ import annotations

import asyncio
import logging

from app.v2.config import settings
from app.v2.db import initialize_database
from app.v2.redis_clients import pubsub_redis, state_redis, stream_redis
from app.v2.services import WorkerPipeline
from app.v2.state import RedisStateStore
from app.v2.streaming import StreamReliabilityManager, StreamMessage


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("siem-worker")


async def run() -> None:
    stream_client = stream_redis()
    pubsub_client = pubsub_redis()
    state_client = state_redis()
    reliability = StreamReliabilityManager(
        stream_client,
        state_client,
        stream_name=settings.ingest_stream,
        group_name=settings.ingest_group,
        consumer_name=settings.worker_id,
    )
    await initialize_database()
    await reliability.ensure_group()
    pipeline = WorkerPipeline(
        stream_client=stream_client,
        pubsub_client=pubsub_client,
        state_store=RedisStateStore(state_client),
    )
    LOGGER.info("worker started stream=%s group=%s id=%s", settings.ingest_stream, settings.ingest_group, settings.worker_id)
    try:
        while True:
            pending = await reliability.pending_summary()
            if pending.get("pending", 0):
                LOGGER.debug("pending ingest messages=%s", pending)

            reclaimed = await reliability.reclaim_stuck(settings.worker_batch_size)
            if reclaimed:
                LOGGER.warning("reclaimed %s stuck ingest messages", len(reclaimed))
            new_messages = await reliability.read_new(settings.worker_batch_size, settings.worker_block_ms)
            for message in reclaimed + new_messages:
                await _process_message(pipeline, reliability, message)
    finally:
        await pubsub_client.aclose()
        await state_client.aclose()
        await stream_client.aclose()


async def _process_message(
    pipeline: WorkerPipeline,
    reliability: StreamReliabilityManager,
    message: StreamMessage,
) -> None:
    payload = message.payload
    try:
        await pipeline.process(
            message_id=message.message_id,
            source_type=str(payload.get("source_type") or "unknown"),
            line=str(payload.get("line") or ""),
            received_at=str(payload.get("received_at")),
            agent_id=payload.get("agent_id"),
            ingest_source_ip=payload.get("ingest_source_ip"),
        )
        await reliability.ack(message.message_id)
    except Exception as exc:
        LOGGER.exception("failed processing ingest message id=%s reclaimed=%s", message.message_id, message.reclaimed)
        outcome = await reliability.fail(
            message_id=message.message_id,
            payload=payload,
            failure_reason="worker_processing_error",
            error=str(exc),
            source_agent=payload.get("agent_id"),
        )
        LOGGER.warning("ingest message failure outcome=%s id=%s", outcome, message.message_id)


if __name__ == "__main__":
    asyncio.run(run())
