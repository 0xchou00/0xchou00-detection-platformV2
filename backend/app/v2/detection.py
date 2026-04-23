from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from app.v2.config import settings
from app.v2.normalizer import NormalizedEvent
from app.v2.state import AbstractStateStore


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


class MatchOperation(BaseModel):
    equals: str | None = None
    contains: str | None = None
    regex: str | None = None

    @field_validator("regex")
    @classmethod
    def validate_regex(cls, value: str | None) -> str | None:
        if value is not None:
            re.compile(value)
        return value


class AggregationRule(BaseModel):
    group_by: str = "source_ip"
    window_seconds: int = 0
    threshold: int = 1
    function: Literal["count", "distinct_count"] = "count"
    field: str | None = None


class SigmaSelection(BaseModel):
    event_type: str | None = None
    source_type: str | None = None


class SigmaLogsource(BaseModel):
    product: str | None = None


class SigmaRule(BaseModel):
    logsource: SigmaLogsource = Field(default_factory=SigmaLogsource)
    detection: dict[str, Any] = Field(default_factory=dict)


class RuleDefinition(BaseModel):
    id: str
    title: str
    description: str
    severity: str = "medium"
    explanation: str
    detection_logic: str
    mitre_attack: list[str] = Field(default_factory=list)
    source_type: str | None = None
    event_type: str | None = None
    match: dict[str, str | MatchOperation] = Field(default_factory=dict)
    aggregation: AggregationRule = Field(default_factory=AggregationRule)
    sigma: SigmaRule | None = None


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
    explanation: str
    detection_logic: str
    mitre_attack: list[str]
    source_type: str | None
    event_type: str | None
    matchers: list[CompiledMatcher]
    aggregation: AggregationRule


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
        for item in payload.get("rules", []):
            try:
                rule = RuleDefinition.model_validate(item)
            except ValidationError as exc:
                raise ValueError(f"Invalid detection rule: {exc}") from exc
            compiled.append(self._compile(rule))
        self._rules = compiled
        self._mtime = current

    def _compile(self, rule: RuleDefinition) -> CompiledRule:
        source_type = rule.source_type
        event_type = rule.event_type
        match_spec = dict(rule.match)
        if rule.sigma is not None:
            selection = (rule.sigma.detection or {}).get("selection", {})
            source_type = source_type or rule.sigma.logsource.product
            event_type = event_type or selection.get("event_type")
            match_spec.update({k: v for k, v in selection.items() if k != "event_type"})
        return CompiledRule(
            rule_id=rule.id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            explanation=rule.explanation,
            detection_logic=rule.detection_logic,
            mitre_attack=list(rule.mitre_attack),
            source_type=source_type,
            event_type=event_type,
            matchers=self._compile_matchers(match_spec),
            aggregation=rule.aggregation,
        )

    def _compile_matchers(self, spec: dict[str, Any]) -> list[CompiledMatcher]:
        matchers: list[CompiledMatcher] = []
        for field_name, expected in spec.items():
            if isinstance(expected, dict):
                op = MatchOperation.model_validate(expected)
                matchers.append(
                    CompiledMatcher(
                        field_name=field_name,
                        equals=op.equals,
                        contains=op.contains,
                        regex=re.compile(op.regex, re.IGNORECASE) if op.regex else None,
                    )
                )
            else:
                matchers.append(CompiledMatcher(field_name=field_name, equals=str(expected)))
        return matchers


class DetectionEngine:
    def __init__(self, state_store: AbstractStateStore, rules_path: Path) -> None:
        self.state = state_store
        self.compiler = RuleCompiler(rules_path)

    async def run(self, event: NormalizedEvent) -> list[Alert]:
        payload = event.to_payload()
        if payload.get("enrichment", {}).get("suppression", {}).get("suppressed"):
            return []
        if event.parser_status != "parsed":
            return []

        alerts: list[Alert] = []
        alerts.extend(await self._builtin_auth_and_network(event, payload))
        alerts.extend(await self._yaml_rules(event, payload))
        return alerts

    async def _builtin_auth_and_network(self, event: NormalizedEvent, payload: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        source_ip = event.source_ip or "unknown"
        username = str(payload.get("username") or "")
        country = ((payload.get("enrichment") or {}).get("geoip") or {}).get("country")

        if event.event_type == "authentication_failure" and source_ip:
            failures = await self.state.count_window("builtin:ssh_fail", source_ip, event.timestamp, 120)
            if failures >= 5:
                if await self._should_emit_builtin("builtin_ssh_bruteforce", source_ip, event.timestamp, 120):
                    alerts.append(
                        self._make_alert(
                        detector="brute_force",
                        rule_id="builtin_ssh_bruteforce",
                        severity="high" if failures < 20 else "critical",
                        title="SSH brute force activity",
                        description=f"Detected {failures} failed SSH logins from {source_ip} in 120 seconds.",
                        event=event,
                        event_count=failures,
                        evidence=[payload],
                        metadata={
                            "explanation": "Repeated SSH authentication failures from one source indicate password guessing.",
                            "detection_logic": "Count authentication_failure events per source_ip over 120 seconds and alert at count >= 5.",
                            "mitre_attack": ["T1110.001"],
                        },
                        )
                    )

            if username:
                distinct_usernames = await self.state.distinct_window(
                    "builtin:ssh_ip_usernames",
                    source_ip,
                    event.timestamp,
                    900,
                    username,
                )
                if distinct_usernames >= 3:
                    if await self._should_emit_builtin(
                        "builtin_multiple_usernames_same_ip", source_ip, event.timestamp, 900
                    ):
                        alerts.append(
                            self._make_alert(
                            detector="auth_anomaly",
                            rule_id="builtin_multiple_usernames_same_ip",
                            severity="high",
                            title="Multiple usernames targeted from one IP",
                            description=f"Source {source_ip} attempted {distinct_usernames} usernames in 15 minutes.",
                            event=event,
                            event_count=distinct_usernames,
                            evidence=[payload],
                            metadata={
                                "explanation": "Credential spraying often targets many usernames from one source.",
                                "detection_logic": "Track distinct usernames per source_ip over 15 minutes and alert at 3 or more.",
                                "mitre_attack": ["T1110.003"],
                            },
                            )
                        )

                distinct_ips = await self.state.distinct_window(
                    "builtin:ssh_username_ips",
                    username,
                    event.timestamp,
                    900,
                    source_ip,
                )
                if distinct_ips >= 3:
                    if await self._should_emit_builtin(
                        "builtin_single_username_many_ips", username, event.timestamp, 900
                    ):
                        alerts.append(
                            self._make_alert(
                            detector="auth_anomaly",
                            rule_id="builtin_single_username_many_ips",
                            severity="high",
                            title="Single username targeted from many IPs",
                            description=f"Username {username} saw failures from {distinct_ips} distinct IPs in 15 minutes.",
                            event=event,
                            event_count=distinct_ips,
                            evidence=[payload],
                            metadata={
                                "explanation": "Distributed password guessing can spread attempts across many sources.",
                                "detection_logic": "Track distinct source_ip values per username over 15 minutes and alert at 3 or more.",
                                "mitre_attack": ["T1110.003"],
                            },
                            )
                        )

        if event.event_type == "network_connection_attempt" and event.destination_port and source_ip:
            distinct_ports = await self.state.distinct_window(
                "builtin:portscan",
                source_ip,
                event.timestamp,
                60,
                str(event.destination_port),
            )
            if distinct_ports >= 8:
                if await self._should_emit_builtin("builtin_port_scan", source_ip, event.timestamp, 60):
                    alerts.append(
                        self._make_alert(
                        detector="port_scan",
                        rule_id="builtin_port_scan",
                        severity="high",
                        title="Port scan behavior",
                        description=f"Source {source_ip} touched {distinct_ports} distinct ports in 60 seconds.",
                        event=event,
                        event_count=distinct_ports,
                        evidence=[payload],
                        metadata={
                            "explanation": "Rapid probing of many ports is a common reconnaissance pattern.",
                            "detection_logic": "Track distinct destination ports per source_ip over 60 seconds and alert at 8 or more.",
                            "mitre_attack": ["T1046"],
                        },
                        )
                    )

        if event.event_type == "authentication_success" and source_ip:
            recent_failures = await self.state.count_window(
                "builtin:ssh_fail",
                source_ip,
                event.timestamp,
                300,
                persist=False,
            )
            if recent_failures >= 3:
                if await self._should_emit_builtin("builtin_success_after_failures", source_ip, event.timestamp, 300):
                    alerts.append(
                        self._make_alert(
                        detector="session_state",
                        rule_id="builtin_success_after_failures",
                        severity="critical",
                        title="SSH success after repeated failures",
                        description=f"Source {source_ip} succeeded after {recent_failures} failures in 5 minutes.",
                        event=event,
                        event_count=recent_failures + 1,
                        evidence=[payload],
                        metadata={
                            "explanation": "A success following repeated failures suggests compromised credentials or brute force success.",
                            "detection_logic": "On authentication_success, inspect prior failures from the same source_ip over 5 minutes and alert at 3 or more.",
                            "mitre_attack": ["T1110.001"],
                        },
                        )
                    )

            if event.timestamp.hour < 6 or event.timestamp.hour >= 22:
                if await self._should_emit_builtin("builtin_unusual_login_time", username or source_ip, event.timestamp, 3600):
                    alerts.append(
                        self._make_alert(
                        detector="auth_anomaly",
                        rule_id="builtin_unusual_login_time",
                        severity="medium",
                        title="Unusual login time",
                        description=f"User {username or 'unknown'} authenticated at {event.timestamp.hour:02d}:00 UTC.",
                        event=event,
                        event_count=1,
                        evidence=[payload],
                        metadata={
                            "explanation": "Off-hours authentication can indicate misuse when there is no business reason for the account to be active.",
                            "detection_logic": "Alert on authentication_success outside 06:00-21:59 UTC.",
                            "mitre_attack": ["T1078"],
                        },
                        )
                    )

            if username:
                seen_ip_key = f"siem:auth:seen_ips:{username}"
                has_seen_this_ip = await self.state.has_set_member(seen_ip_key, source_ip)
                distinct_seen_ips = await self.state.set_cardinality(seen_ip_key)
                if distinct_seen_ips > 0 and not has_seen_this_ip:
                    if await self._should_emit_builtin("builtin_new_source_ip_login", username, event.timestamp, 86400):
                        alerts.append(
                            self._make_alert(
                            detector="auth_anomaly",
                            rule_id="builtin_new_source_ip_login",
                            severity="medium",
                            title="Login from a new source IP",
                            description=f"User {username} logged in from unseen source IP {source_ip}.",
                            event=event,
                            event_count=distinct_seen_ips + 1,
                            evidence=[payload],
                            metadata={
                                "explanation": "A new source IP for an account may indicate account sharing, travel, or compromise.",
                                "detection_logic": "Remember successful login source IPs per username and alert when a new IP appears after a baseline exists.",
                                "mitre_attack": ["T1078"],
                            },
                            )
                        )
                await self.state.add_to_set(seen_ip_key, source_ip, settings.state_default_ttl_seconds)

                rare_key = f"siem:auth:rare_user:{username}"
                seen_user_before = await self.state.has_set_member("siem:auth:rare_users", username)
                if not seen_user_before:
                    if await self._should_emit_builtin("builtin_rare_authentication_event", username, event.timestamp, 86400):
                        alerts.append(
                            self._make_alert(
                            detector="auth_anomaly",
                            rule_id="builtin_rare_authentication_event",
                            severity="low",
                            title="Rare authentication event",
                            description=f"User {username} has no prior successful login in current state history.",
                            event=event,
                            event_count=1,
                            evidence=[payload],
                            metadata={
                                "explanation": "A first-seen successful login can be benign or can mark the first use of a compromised account.",
                                "detection_logic": "Track seen usernames for successful authentication and alert when a username has not been seen before.",
                                "mitre_attack": ["T1078"],
                            },
                            )
                        )
                await self.state.add_to_set("siem:auth:rare_users", username, settings.state_default_ttl_seconds)
                await self.state.add_to_set(rare_key, source_ip, settings.state_default_ttl_seconds)

                previous_login = await self.state.get_json(f"siem:auth:last_login:{username}")
                if previous_login and previous_login.get("country") and country:
                    if previous_login["country"] != country and previous_login["country"] not in {"LAB", "PRIVATE"} and country not in {"LAB", "PRIVATE"}:
                        previous_ts = datetime.fromisoformat(previous_login["timestamp"])
                        if int((event.timestamp - previous_ts).total_seconds()) <= 3600:
                            if await self._should_emit_builtin(
                                "builtin_impossible_login_pattern", username, event.timestamp, 3600
                            ):
                                alerts.append(
                                    self._make_alert(
                                    detector="auth_anomaly",
                                    rule_id="builtin_impossible_login_pattern",
                                    severity="high",
                                    title="Impossible login pattern",
                                    description=(
                                        f"User {username} authenticated from {previous_login['country']} and {country} within one hour."
                                    ),
                                    event=event,
                                    event_count=2,
                                    evidence=[previous_login, payload],
                                    metadata={
                                        "explanation": "Two successful logins from materially different geographies in a short period can indicate credential compromise.",
                                        "detection_logic": "Compare the current successful login country with the previous successful login country for the same username and alert when they differ within one hour.",
                                        "mitre_attack": ["T1078"],
                                    },
                                    )
                                )

                await self.state.set_json(
                    f"siem:auth:last_login:{username}",
                    {"timestamp": event.timestamp.isoformat(), "country": country, "source_ip": source_ip},
                    settings.state_default_ttl_seconds,
                )

        return alerts

    async def _should_emit_builtin(
        self,
        rule_id: str,
        group: str,
        event_time: datetime,
        window_seconds: int,
    ) -> bool:
        bucket = int(event_time.timestamp()) // max(window_seconds, 60)
        return await self.state.dedupe(
            f"siem:state:builtin-dedupe:{rule_id}:{group}:{bucket}",
            max(window_seconds, 60),
        )

    async def _yaml_rules(self, event: NormalizedEvent, payload: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.compiler.rules:
            if rule.source_type and rule.source_type != event.source_type:
                continue
            if rule.event_type and rule.event_type != event.event_type:
                continue
            if not all(matcher.matches(payload) for matcher in rule.matchers):
                continue

            event_count = 1
            if rule.aggregation.window_seconds > 0:
                group_value = str(payload.get(rule.aggregation.group_by) or "global")
                if rule.aggregation.function == "distinct_count" and rule.aggregation.field:
                    distinct_value = str(payload.get(rule.aggregation.field) or "__none__")
                    event_count = await self.state.distinct_window(
                        f"rule:{rule.rule_id}",
                        group_value,
                        event.timestamp,
                        rule.aggregation.window_seconds,
                        distinct_value,
                    )
                else:
                    event_count = await self.state.count_window(
                        f"rule:{rule.rule_id}",
                        group_value,
                        event.timestamp,
                        rule.aggregation.window_seconds,
                    )
                if event_count < rule.aggregation.threshold:
                    continue
                bucket = int(event.timestamp.timestamp() // max(rule.aggregation.window_seconds, 1))
                dedupe_key = f"siem:state:dedupe:{rule.rule_id}:{group_value}:{bucket}"
                if not await self.state.dedupe(dedupe_key, max(rule.aggregation.window_seconds, 60)):
                    continue

            alerts.append(
                self._make_alert(
                    detector="yaml_rules",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    event=event,
                    event_count=event_count,
                    evidence=[payload],
                    metadata={
                        "explanation": rule.explanation,
                        "detection_logic": rule.detection_logic,
                        "mitre_attack": rule.mitre_attack,
                        "aggregation": rule.aggregation.model_dump(),
                    },
                )
            )
        return alerts

    def _make_alert(
        self,
        *,
        detector: str,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        event: NormalizedEvent,
        event_count: int,
        evidence: list[dict[str, Any]],
        metadata: dict[str, Any],
    ) -> Alert:
        return Alert(
            detector=detector,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            source_type=event.source_type,
            source_ip=event.source_ip,
            event_count=event_count,
            evidence=evidence,
            metadata=metadata,
        )


def hash_payload(payload: dict[str, Any]) -> str:
    material = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
