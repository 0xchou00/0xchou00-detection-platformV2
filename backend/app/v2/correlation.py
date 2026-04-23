from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from redis.asyncio import Redis

from app.v2.detection import Alert


@dataclass(slots=True)
class CorrelationStage:
    detector: str
    rule_id: str | None = None


@dataclass(slots=True)
class CorrelationRule:
    rule_id: str
    title: str
    description: str
    severity: str
    window_seconds: int
    group_by: str
    sequence: list[CorrelationStage]


class CorrelationEngine:
    def __init__(self, redis_client: Redis, rules_path: Path) -> None:
        self.redis = redis_client
        self.rules_path = rules_path
        self._rules: list[CorrelationRule] = []
        self._mtime: float | None = None
        self._reload(force=True)

    async def run(self, alert: Alert) -> list[Alert]:
        self._reload()
        group = alert.source_ip
        if not group:
            return []

        event = {
            "id": alert.alert_id,
            "detector": alert.detector,
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "title": alert.title,
            "created_at": alert.created_at.astimezone(timezone.utc).isoformat(),
        }
        key = f"siem:corr:history:{group}"
        ts = int(alert.created_at.timestamp())
        await self.redis.zadd(key, {json.dumps(event, sort_keys=True): ts})
        await self.redis.zremrangebyscore(key, 0, ts - 7200)
        await self.redis.expire(key, 10800)

        history_raw = await self.redis.zrangebyscore(key, ts - 7200, ts)
        history = [json.loads(item) for item in history_raw]
        history.sort(key=lambda item: item["created_at"])

        generated: list[Alert] = []
        for rule in self._rules:
            if not self._matches_sequence(history, rule, alert.created_at):
                continue
            fingerprint = self._fingerprint(rule.rule_id, group, alert.created_at, history)
            if not await self.redis.set(f"siem:corr:dedupe:{fingerprint}", "1", ex=rule.window_seconds, nx=True):
                continue
            generated.append(
                Alert(
                    detector="correlation",
                    rule_id=rule.rule_id,
                    alert_kind="correlation",
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    source_type=alert.source_type,
                    source_ip=group,
                    event_count=len(rule.sequence),
                    evidence=history[-len(rule.sequence) :],
                    metadata={
                        "correlation_rule_id": rule.rule_id,
                        "group_by": rule.group_by,
                        "matched_sequence": [stage.detector for stage in rule.sequence],
                        "fingerprint": fingerprint,
                    },
                    alert_id=uuid.uuid4().hex,
                )
            )
        return generated

    def _reload(self, force: bool = False) -> None:
        if not self.rules_path.exists():
            self._rules = []
            self._mtime = None
            return
        mtime = self.rules_path.stat().st_mtime
        if not force and self._mtime == mtime:
            return
        payload = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        rules: list[CorrelationRule] = []
        for item in payload.get("rules", []):
            seq = []
            for stage in item.get("sequence", []):
                if not isinstance(stage, dict) or not stage.get("detector"):
                    continue
                seq.append(CorrelationStage(detector=str(stage["detector"]), rule_id=stage.get("rule_id")))
            if not seq:
                continue
            rules.append(
                CorrelationRule(
                    rule_id=str(item["id"]),
                    title=str(item.get("title", item["id"])),
                    description=str(item.get("description", item.get("title", item["id"]))),
                    severity=str(item.get("severity", "high")),
                    window_seconds=int(item.get("window_seconds", 600)),
                    group_by=str(item.get("group_by", "source_ip")),
                    sequence=seq,
                )
            )
        self._rules = rules
        self._mtime = mtime

    def _matches_sequence(
        self,
        history: list[dict[str, Any]],
        rule: CorrelationRule,
        now: datetime,
    ) -> bool:
        min_time = now.astimezone(timezone.utc).timestamp() - rule.window_seconds
        bounded_history = [
            item for item in history if datetime.fromisoformat(item["created_at"]).timestamp() >= min_time
        ]
        sequence = list(rule.sequence)
        index = 0
        for item in bounded_history:
            stage = sequence[index]
            if item.get("detector") != stage.detector:
                continue
            if stage.rule_id and item.get("rule_id") != stage.rule_id:
                continue
            index += 1
            if index == len(sequence):
                return True
        return False

    def _fingerprint(
        self,
        rule_id: str,
        group: str,
        created_at: datetime,
        history: list[dict[str, Any]],
    ) -> str:
        material = {
            "rule_id": rule_id,
            "group": group,
            "bucket": int(created_at.timestamp()) // 300,
            "tail": [(item.get("detector"), item.get("rule_id"), item.get("created_at")) for item in history[-8:]],
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()
