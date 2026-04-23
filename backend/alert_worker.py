from __future__ import annotations

import asyncio
import json
import logging

from app.v2.config import settings
from app.v2.redis_clients import state_redis, stream_redis
from app.v2.services import AlertDispatcher
from app.v2.state import RedisStateStore
from app.v2.streaming import StreamReliabilityManager, StreamMessage


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("siem-alert-worker")


async def run() -> None:
    stream_client = stream_redis()
    state_client = state_redis()
    reliability = StreamReliabilityManager(
        stream_client,
        state_client,
        stream_name=settings.alert_stream,
        group_name=settings.alert_group,
        consumer_name=settings.alerter_id,
    )
    await reliability.ensure_group()
    dispatcher = AlertDispatcher(state_store=RedisStateStore(state_client))
    LOGGER.info("alert worker started stream=%s group=%s id=%s", settings.alert_stream, settings.alert_group, settings.alerter_id)
    try:
        while True:
            reclaimed = await reliability.reclaim_stuck(100)
            if reclaimed:
                LOGGER.warning("reclaimed %s stuck alert messages", len(reclaimed))
            new_messages = await reliability.read_new(100, 4000)
            for message in reclaimed + new_messages:
                await _dispatch(dispatcher, reliability, message)
    finally:
        await state_client.aclose()
        await stream_client.aclose()


async def _dispatch(
    dispatcher: AlertDispatcher,
    reliability: StreamReliabilityManager,
    message: StreamMessage,
) -> None:
    try:
        alert = json.loads(str(message.payload.get("alert") or "{}"))
        await dispatcher.deliver(alert)
        await reliability.ack(message.message_id)
    except Exception as exc:
        LOGGER.exception("failed dispatching alert id=%s", message.message_id)
        outcome = await reliability.fail(
            message_id=message.message_id,
            payload=message.payload,
            failure_reason="alert_delivery_error",
            error=str(exc),
            source_agent=message.payload.get("source_agent"),
        )
        LOGGER.warning("alert message failure outcome=%s id=%s", outcome, message.message_id)


if __name__ == "__main__":
    asyncio.run(run())
