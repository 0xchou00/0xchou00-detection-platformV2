from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from redis.asyncio import Redis


class AbstractStateStore(ABC):
    @abstractmethod
    async def count_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        *,
        persist: bool = True,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    async def distinct_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        value: str,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    async def dedupe(self, key: str, ttl_seconds: int) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        raise NotImplementedError

    @abstractmethod
    async def get_json(self, key: str) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    async def add_to_set(self, key: str, value: str, ttl_seconds: int) -> None:
        raise NotImplementedError

    @abstractmethod
    async def set_cardinality(self, key: str) -> int:
        raise NotImplementedError

    @abstractmethod
    async def has_set_member(self, key: str, value: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def add_sorted_json(self, key: str, score: int, value: dict[str, Any], ttl_seconds: int) -> None:
        raise NotImplementedError

    @abstractmethod
    async def range_sorted_json(self, key: str, min_score: int, max_score: int) -> list[dict[str, Any]]:
        raise NotImplementedError


class RedisStateStore(AbstractStateStore):
    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    async def count_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        *,
        persist: bool = True,
    ) -> int:
        key = f"siem:state:{namespace}:{group}:count"
        ts = int(event_time.timestamp())
        pipe = self.redis.pipeline()
        if persist:
            member = f"{ts}:{time.time_ns()}"
            pipe.zadd(key, {member: ts})
        pipe.zremrangebyscore(key, 0, ts - window_seconds - 1)
        pipe.zcount(key, ts - window_seconds, ts)
        pipe.expire(key, max(window_seconds * 3, 60))
        results = await pipe.execute()
        return int(results[2] if persist else results[1])

    async def distinct_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        value: str,
    ) -> int:
        key = f"siem:state:{namespace}:{group}:distinct"
        ts = int(event_time.timestamp())
        pipe = self.redis.pipeline()
        pipe.zadd(key, {value: ts})
        pipe.zremrangebyscore(key, 0, ts - window_seconds - 1)
        pipe.zcount(key, ts - window_seconds, ts)
        pipe.expire(key, max(window_seconds * 3, 60))
        _, _, count, _ = await pipe.execute()
        return int(count)

    async def dedupe(self, key: str, ttl_seconds: int) -> bool:
        return bool(await self.redis.set(key, "1", ex=ttl_seconds, nx=True))

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        await self.redis.set(key, json.dumps(value, sort_keys=True, default=str), ex=ttl_seconds)

    async def get_json(self, key: str) -> dict[str, Any] | None:
        raw = await self.redis.get(key)
        return json.loads(raw) if raw else None

    async def add_to_set(self, key: str, value: str, ttl_seconds: int) -> None:
        await self.redis.sadd(key, value)
        await self.redis.expire(key, ttl_seconds)

    async def set_cardinality(self, key: str) -> int:
        return int(await self.redis.scard(key))

    async def has_set_member(self, key: str, value: str) -> bool:
        return bool(await self.redis.sismember(key, value))

    async def add_sorted_json(self, key: str, score: int, value: dict[str, Any], ttl_seconds: int) -> None:
        await self.redis.zadd(key, {json.dumps(value, sort_keys=True, default=str): score})
        await self.redis.expire(key, ttl_seconds)

    async def range_sorted_json(self, key: str, min_score: int, max_score: int) -> list[dict[str, Any]]:
        rows = await self.redis.zrangebyscore(key, min_score, max_score)
        return [json.loads(item) for item in rows]


@dataclass
class _ExpiryValue:
    expires_at: float
    value: Any


class InMemoryStateStore(AbstractStateStore):
    def __init__(self) -> None:
        self._zsets: dict[str, dict[str, int]] = defaultdict(dict)
        self._values: dict[str, _ExpiryValue] = {}
        self._sets: dict[str, set[str]] = defaultdict(set)

    async def count_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        *,
        persist: bool = True,
    ) -> int:
        key = f"count:{namespace}:{group}"
        ts = int(event_time.timestamp())
        if persist:
            self._zsets[key][f"{ts}:{time.time_ns()}"] = ts
        self._trim_zset(key, ts - window_seconds - 1)
        return sum(1 for score in self._zsets[key].values() if ts - window_seconds <= score <= ts)

    async def distinct_window(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        value: str,
    ) -> int:
        key = f"distinct:{namespace}:{group}"
        ts = int(event_time.timestamp())
        self._zsets[key][value] = ts
        self._trim_zset(key, ts - window_seconds - 1)
        return sum(1 for score in self._zsets[key].values() if ts - window_seconds <= score <= ts)

    async def dedupe(self, key: str, ttl_seconds: int) -> bool:
        current = self._values.get(key)
        if current and current.expires_at > time.time():
            return False
        self._values[key] = _ExpiryValue(time.time() + ttl_seconds, "1")
        return True

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        self._values[key] = _ExpiryValue(time.time() + ttl_seconds, value)

    async def get_json(self, key: str) -> dict[str, Any] | None:
        current = self._values.get(key)
        if not current or current.expires_at <= time.time():
            return None
        return current.value

    async def add_to_set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._sets[key].add(value)
        self._values[f"ttl:{key}"] = _ExpiryValue(time.time() + ttl_seconds, True)

    async def set_cardinality(self, key: str) -> int:
        self._expire_set_if_needed(key)
        return len(self._sets[key])

    async def has_set_member(self, key: str, value: str) -> bool:
        self._expire_set_if_needed(key)
        return value in self._sets[key]

    async def add_sorted_json(self, key: str, score: int, value: dict[str, Any], ttl_seconds: int) -> None:
        self._zsets[key][json.dumps(value, sort_keys=True, default=str)] = score
        self._values[f"ttl:{key}"] = _ExpiryValue(time.time() + ttl_seconds, True)

    async def range_sorted_json(self, key: str, min_score: int, max_score: int) -> list[dict[str, Any]]:
        self._expire_zset_if_needed(key)
        items = []
        for payload, score in self._zsets[key].items():
            if min_score <= score <= max_score:
                items.append(json.loads(payload))
        items.sort(key=lambda item: item.get("created_at", ""))
        return items

    def _trim_zset(self, key: str, min_score: int) -> None:
        self._zsets[key] = {member: score for member, score in self._zsets[key].items() if score >= min_score}

    def _expire_set_if_needed(self, key: str) -> None:
        ttl = self._values.get(f"ttl:{key}")
        if ttl and ttl.expires_at <= time.time():
            self._sets.pop(key, None)
            self._values.pop(f"ttl:{key}", None)

    def _expire_zset_if_needed(self, key: str) -> None:
        ttl = self._values.get(f"ttl:{key}")
        if ttl and ttl.expires_at <= time.time():
            self._zsets.pop(key, None)
            self._values.pop(f"ttl:{key}", None)

