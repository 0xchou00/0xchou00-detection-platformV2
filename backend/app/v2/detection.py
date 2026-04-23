from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from redis.asyncio import Redis

from app.v2.normalizer import NormalizedEvent


@dataclass(slots=True)
class Alert:
    detector: str
    severity: str
    title: str
    description: str
    source_type: str
    source_ip: str | None
    event_count: int
    evidence: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    rule_id: str | None = None
    alert_kind: str = "detection"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert_id,
            "detector": self.detector,
            "rule_id": self.rule_id,
            "alert_kind": self.alert_kind,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_type": self.source_type,
            "source_ip": self.source_ip,
            "event_count": self.event_count,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
        }


@dataclass(slots=True)
class CompiledMatcher:
    field_name: str
    equals: str | None = None
    contains: str | None = None
    regex: re.Pattern[str] | None = None

    def matches(self, payload: dict[str, Any]) -> bool:
        value = payload.get(self.field_name)
        text = "" if value is None else str(value)
        if self.equals is not None and text != self.equals:
            return False
        if self.contains is not None and self.contains.lower() not in text.lower():
            return False
        if self.regex is not None and self.regex.search(text) is None:
            return False
        return True


@dataclass(slots=True)
class CompiledRule:
    rule_id: str
    title: str
    description: str
    severity: str
    source_type: str | None
    event_type: str | None
    matchers: list[CompiledMatcher]
    group_by: str = "source_ip"
    window_seconds: int = 0
    threshold: int = 1
    function: str = "count"
    distinct_field: str | None = None


class RuleCompiler:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self._rules: list[CompiledRule] = []
        self._mtime: float | None = None
        self.reload_if_changed(force=True)

    @property
    def rules(self) -> list[CompiledRule]:
        self.reload_if_changed()
        return self._rules

    def reload_if_changed(self, force: bool = False) -> None:
        if not self.rules_path.exists():
            self._rules = []
            self._mtime = None
            return
        current = self.rules_path.stat().st_mtime
        if not force and self._mtime == current:
            return
        payload = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        compiled: list[CompiledRule] = []
        for rule in payload.get("rules", []):
            if not isinstance(rule, dict) or not rule.get("id"):
                continue
            if "sigma" in rule:
                compiled.append(self._compile_sigma(rule))
            else:
                compiled.append(self._compile_native(rule))
        self._rules = compiled
        self._mtime = current

    def _compile_native(self, rule: dict[str, Any]) -> CompiledRule:
        aggregation = rule.get("aggregation", {}) or {}
        return CompiledRule(
            rule_id=str(rule["id"]),
            title=str(rule.get("title", rule["id"])),
            description=str(rule.get("description", rule.get("title", rule["id"]))),
            severity=str(rule.get("severity", "medium")),
            source_type=rule.get("source_type"),
            event_type=rule.get("event_type"),
            matchers=self._compile_matchers(rule.get("match", {})),
            group_by=str(aggregation.get("group_by", "source_ip")),
            window_seconds=int(aggregation.get("window_seconds", 0)),
            threshold=int(aggregation.get("threshold", 1)),
            function=str(aggregation.get("function", "count")),
            distinct_field=aggregation.get("field"),
        )

    def _compile_sigma(self, rule: dict[str, Any]) -> CompiledRule:
        sigma = rule["sigma"] or {}
        detection = sigma.get("detection", {})
        selection = detection.get("selection", {})
        return CompiledRule(
            rule_id=str(rule["id"]),
            title=str(rule.get("title", rule["id"])),
            description=str(rule.get("description", rule.get("title", rule["id"]))),
            severity=str(rule.get("severity", "medium")),
            source_type=(sigma.get("logsource", {}) or {}).get("product"),
            event_type=selection.get("event_type"),
            matchers=self._compile_matchers(selection),
            group_by=str((rule.get("aggregation", {}) or {}).get("group_by", "source_ip")),
            window_seconds=int((rule.get("aggregation", {}) or {}).get("window_seconds", 0)),
            threshold=int((rule.get("aggregation", {}) or {}).get("threshold", 1)),
            function=str((rule.get("aggregation", {}) or {}).get("function", "count")),
            distinct_field=(rule.get("aggregation", {}) or {}).get("field"),
        )

    def _compile_matchers(self, match_spec: dict[str, Any]) -> list[CompiledMatcher]:
        matchers: list[CompiledMatcher] = []
        for field_name, expected in (match_spec or {}).items():
            if field_name == "event_type":
                continue
            if isinstance(expected, dict):
                matcher = CompiledMatcher(
                    field_name=field_name,
                    equals=str(expected["equals"]) if "equals" in expected else None,
                    contains=str(expected["contains"]) if "contains" in expected else None,
                    regex=re.compile(str(expected["regex"]), re.IGNORECASE) if "regex" in expected else None,
                )
            else:
                matcher = CompiledMatcher(field_name=field_name, equals=str(expected))
            matchers.append(matcher)
        return matchers


class DetectionEngine:
    def __init__(self, redis_client: Redis, rules_path: Path) -> None:
        self.redis = redis_client
        self.compiler = RuleCompiler(rules_path)

    async def run(self, event: NormalizedEvent) -> list[Alert]:
        payload = self._flatten_event(event)
        alerts: list[Alert] = []
        alerts.extend(await self._builtins(event, payload))
        alerts.extend(await self._yaml_rules(event, payload))
        return alerts

    async def _builtins(self, event: NormalizedEvent, payload: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        source_ip = event.source_ip or "unknown"
        if event.event_type == "authentication_failure" and source_ip:
            failures = await self._window_count("builtin:ssh_fail", source_ip, event.timestamp, 120)
            if failures >= 5:
                alerts.append(
                    Alert(
                        detector="brute_force",
                        rule_id="builtin_ssh_bruteforce",
                        severity="high" if failures < 20 else "critical",
                        title="SSH brute force activity",
                        description=f"Detected {failures} failed SSH logins from {source_ip} in 120s.",
                        source_type=event.source_type,
                        source_ip=source_ip,
                        event_count=failures,
                        evidence=[payload],
                        metadata={"window_seconds": 120, "threshold": 5, "stateful_key": source_ip},
                    )
                )

        if event.event_type == "network_connection_attempt" and event.destination_port and source_ip:
            distinct = await self._window_distinct(
                "builtin:portscan",
                source_ip,
                event.timestamp,
                60,
                str(event.destination_port),
            )
            if distinct >= 8:
                alerts.append(
                    Alert(
                        detector="port_scan",
                        rule_id="builtin_port_scan",
                        severity="high",
                        title="Port scan behavior",
                        description=f"Source {source_ip} touched {distinct} distinct ports in 60s.",
                        source_type=event.source_type,
                        source_ip=source_ip,
                        event_count=distinct,
                        evidence=[payload],
                        metadata={"window_seconds": 60, "threshold": 8, "distinct_field": "destination_port"},
                    )
                )

        if event.event_type == "authentication_success" and source_ip:
            recent_failures = await self._window_count("builtin:ssh_fail", source_ip, event.timestamp, 300, persist=False)
            if recent_failures >= 3:
                alerts.append(
                    Alert(
                        detector="session_state",
                        rule_id="builtin_success_after_failures",
                        severity="critical",
                        title="SSH success after repeated failures",
                        description=(
                            f"Source {source_ip} achieved successful SSH auth after {recent_failures} failures in 5m."
                        ),
                        source_type=event.source_type,
                        source_ip=source_ip,
                        event_count=recent_failures + 1,
                        evidence=[payload],
                        metadata={"session_state": "success_after_failures", "recent_failures": recent_failures},
                    )
                )
        return alerts

    async def _yaml_rules(self, event: NormalizedEvent, payload: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.compiler.rules:
            if rule.source_type and rule.source_type != event.source_type:
                continue
            if rule.event_type and rule.event_type != event.event_type:
                continue
            if not all(matcher.matches(payload) for matcher in rule.matchers):
                continue

            group_value = str(payload.get(rule.group_by) or "global")
            event_count = 1
            if rule.window_seconds > 0:
                if rule.function == "distinct_count" and rule.distinct_field:
                    distinct_value = str(payload.get(rule.distinct_field) or "__none__")
                    event_count = await self._window_distinct(
                        f"rule:{rule.rule_id}",
                        group_value,
                        event.timestamp,
                        rule.window_seconds,
                        distinct_value,
                    )
                else:
                    event_count = await self._window_count(
                        f"rule:{rule.rule_id}",
                        group_value,
                        event.timestamp,
                        rule.window_seconds,
                    )
                if event_count < rule.threshold:
                    continue

                dedupe_bucket = int(event.timestamp.timestamp() // max(rule.window_seconds, 1))
                if await self._seen_dedupe(rule.rule_id, group_value, dedupe_bucket):
                    continue
            alerts.append(
                Alert(
                    detector="yaml_rules",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    source_type=event.source_type,
                    source_ip=event.source_ip,
                    event_count=event_count,
                    evidence=[payload],
                    metadata={
                        "rule_id": rule.rule_id,
                        "window_seconds": rule.window_seconds,
                        "threshold": rule.threshold,
                        "group_by": rule.group_by,
                    },
                )
            )
        return alerts

    async def _window_count(
        self,
        namespace: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
        persist: bool = True,
    ) -> int:
        key = f"siem:state:{namespace}:{group}:count"
        ts = int(event_time.timestamp())
        pipe = self.redis.pipeline()
        if persist:
            member = f"{ts}:{uuid.uuid4().hex}"
            pipe.zadd(key, {member: ts})
        pipe.zremrangebyscore(key, 0, ts - window_seconds - 1)
        pipe.zcount(key, ts - window_seconds, ts)
        pipe.expire(key, max(window_seconds * 3, 60))
        results = await pipe.execute()
        count = results[2] if persist else results[1]
        return int(count)

    async def _window_distinct(
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

    async def _seen_dedupe(self, rule_id: str, group: str, bucket: int) -> bool:
        key = f"siem:state:dedupe:{rule_id}:{group}:{bucket}"
        return not bool(await self.redis.set(key, "1", ex=3600, nx=True))

    def _flatten_event(self, event: NormalizedEvent) -> dict[str, Any]:
        payload = event.to_payload()
        for key, value in (event.metadata or {}).items():
            payload[key] = value
        return payload


def hash_payload(payload: dict[str, Any]) -> str:
    material = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def iter_rule_ids(alerts: Iterable[Alert]) -> list[str]:
    return [alert.rule_id for alert in alerts if alert.rule_id]
