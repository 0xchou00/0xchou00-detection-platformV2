from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis

from app.v2.config import settings


@dataclass(slots=True)
class StreamMessage:
    message_id: str
    payload: dict[str, Any]
    reclaimed: bool = False


class StreamReliabilityManager:
    def __init__(
        self,
        stream_client: Redis,
        state_client: Redis,
        *,
        stream_name: str,
        group_name: str,
        consumer_name: str,
    ) -> None:
        self.stream = stream_client
        self.state = state_client
        self.stream_name = stream_name
        self.group_name = group_name
        self.consumer_name = consumer_name

    async def ensure_group(self) -> None:
        try:
            await self.stream.xgroup_create(self.stream_name, self.group_name, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def pending_summary(self) -> dict[str, Any]:
        try:
            summary = await self.stream.xpending(self.stream_name, self.group_name)
        except Exception:
            return {"pending": 0, "min_id": None, "max_id": None, "consumers": []}

        return {
            "pending": int(summary["pending"]) if isinstance(summary, dict) else int(summary[0]),
            "min_id": summary["min"] if isinstance(summary, dict) else summary[1],
            "max_id": summary["max"] if isinstance(summary, dict) else summary[2],
            "consumers": summary["consumers"] if isinstance(summary, dict) else summary[3],
        }

    async def reclaim_stuck(self, count: int) -> list[StreamMessage]:
        next_start = "0-0"
        reclaimed: list[StreamMessage] = []
        remaining = max(count, 1)
        while remaining > 0:
            messages, next_start = await self._xautoclaim(next_start, remaining)
            if not messages:
                break
            for message_id, payload in messages:
                reclaimed.append(StreamMessage(message_id=message_id, payload=payload, reclaimed=True))
            remaining -= len(messages)
            if next_start == "0-0":
                break
        return reclaimed

    async def read_new(self, count: int, block_ms: int) -> list[StreamMessage]:
        records = await self.stream.xreadgroup(
            groupname=self.group_name,
            consumername=self.consumer_name,
            streams={self.stream_name: ">"},
            count=count,
            block=block_ms,
        )
        messages: list[StreamMessage] = []
        for _, items in records:
            for message_id, payload in items:
                messages.append(StreamMessage(message_id=message_id, payload=payload, reclaimed=False))
        return messages

    async def ack(self, message_id: str) -> None:
        await self.stream.xack(self.stream_name, self.group_name, message_id)

    async def fail(
        self,
        *,
        message_id: str,
        payload: dict[str, Any],
        failure_reason: str,
        error: str,
        source_agent: str | None,
    ) -> dict[str, Any]:
        retry_key = f"siem:retry:{self.stream_name}:{message_id}"
        retries = int(await self.state.incr(retry_key))
        await self.state.expire(retry_key, settings.stream_retry_ttl_seconds)

        if retries >= settings.stream_retry_limit:
            dead_letter_payload = {
                "stream": self.stream_name,
                "group": self.group_name,
                "message_id": message_id,
                "original_payload": json.dumps(payload, sort_keys=True, default=str),
                "failure_reason": failure_reason,
                "retry_count": retries,
                "last_processing_error": error,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_agent": source_agent or payload.get("agent_id") or "unknown",
            }
            await self.stream.xadd(
                settings.dead_letter_stream,
                dead_letter_payload,
                maxlen=settings.stream_maxlen,
                approximate=True,
            )
            await self.ack(message_id)
            await self.state.delete(retry_key)
            return {"status": "dead_lettered", "retry_count": retries}

        return {"status": "pending_retry", "retry_count": retries}

    async def dead_letter_items(self, limit: int) -> list[dict[str, Any]]:
        rows = await self.stream.xrevrange(settings.dead_letter_stream, count=limit)
        items: list[dict[str, Any]] = []
        for message_id, payload in rows:
            item = dict(payload)
            item["id"] = message_id
            original_payload = item.get("original_payload")
            if original_payload:
                try:
                    item["original_payload"] = json.loads(original_payload)
                except json.JSONDecodeError:
                    pass
            items.append(item)
        return items

    async def dead_letter_count(self) -> int:
        return int(await self.stream.xlen(settings.dead_letter_stream))

    async def _xautoclaim(self, start_id: str, count: int) -> tuple[list[tuple[str, dict[str, Any]]], str]:
        result = await self.stream.xautoclaim(
            name=self.stream_name,
            groupname=self.group_name,
            consumername=self.consumer_name,
            min_idle_time=settings.stream_claim_idle_ms,
            start_id=start_id,
            count=count,
        )
        next_start = result[0]
        messages = result[1]
        return messages, next_start
