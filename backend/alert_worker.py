from __future__ import annotations

import asyncio
import json
import logging

from redis.asyncio import Redis

from app.v2.config import settings
from app.v2.services import AlertDispatcher


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("siem-alert-worker")


async def _ensure_group(redis_client: Redis, stream: str, group: str) -> None:
    try:
        await redis_client.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def run() -> None:
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    await _ensure_group(redis_client, settings.alert_stream, settings.alert_group)
    dispatcher = AlertDispatcher()
    LOGGER.info("alert worker started stream=%s group=%s id=%s", settings.alert_stream, settings.alert_group, settings.alerter_id)
    while True:
        records = await redis_client.xreadgroup(
            groupname=settings.alert_group,
            consumername=settings.alerter_id,
            streams={settings.alert_stream: ">"},
            count=100,
            block=4000,
        )
        if not records:
            continue
        for _, items in records:
            for message_id, payload in items:
                try:
                    alert = json.loads(payload["alert"])
                    await dispatcher.deliver(alert)
                    await redis_client.xack(settings.alert_stream, settings.alert_group, message_id)
                except Exception:
                    LOGGER.exception("failed dispatching alert id=%s", message_id)


if __name__ == "__main__":
    asyncio.run(run())

