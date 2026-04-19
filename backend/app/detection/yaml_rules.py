from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from app.detection.base import BaseDetector
from app.models.alert import Alert
from app.models.event import LogEvent


@dataclass(slots=True)
class YAMLRule:
    rule_id: str
    title: str
    description: str
    severity: str
    source_type: str | None = None
    event_type: str | None = None
    match: dict[str, Any] = field(default_factory=dict)
    aggregation: dict[str, Any] | None = None


class YAMLRuleDetector(BaseDetector):
    name = "yaml_rules"

    def __init__(self, rules_file: Path) -> None:
        self.rules_file = Path(rules_file)
        self._rules: list[YAMLRule] = []
        self._aggregations: dict[str, dict[str, deque[tuple[object, dict[str, Any]]]]] = defaultdict(
            lambda: defaultdict(deque)
        )
        self._alerted_windows: set[tuple[str, str, int]] = set()
        self._last_loaded_mtime: float | None = None
        self._load_rules()

    def process(self, event: LogEvent) -> list[Alert]:
        self._reload_if_changed()
        alerts: list[Alert] = []

        for rule in self._rules:
            if not self._event_matches_rule(event, rule):
                continue

            if rule.aggregation:
                alert = self._evaluate_aggregation_rule(event, rule)
                if alert:
                    alerts.append(alert)
                continue

            alerts.append(self._build_alert(event, rule, event_count=1))

        return alerts

    def reset(self) -> None:
        self._aggregations.clear()
        self._alerted_windows.clear()

    def _load_rules(self) -> None:
        if not self.rules_file.exists():
            self._rules = []
            self._last_loaded_mtime = None
            return

        with self.rules_file.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}

        self._rules = [
            YAMLRule(
                rule_id=item["id"],
                title=item["title"],
                description=item.get("description", item["title"]),
                severity=item.get("severity", "medium"),
                source_type=item.get("source_type"),
                event_type=item.get("event_type"),
                match=item.get("match", {}),
                aggregation=item.get("aggregation"),
            )
            for item in payload.get("rules", [])
            if isinstance(item, dict) and item.get("id") and item.get("title")
        ]
        self._last_loaded_mtime = self.rules_file.stat().st_mtime

    def _reload_if_changed(self) -> None:
        if not self.rules_file.exists():
            return
        current_mtime = self.rules_file.stat().st_mtime
        if self._last_loaded_mtime != current_mtime:
            self._load_rules()

    def _event_matches_rule(self, event: LogEvent, rule: YAMLRule) -> bool:
        if rule.source_type and event.source_type != rule.source_type:
            return False
        if rule.event_type and event.event_type != rule.event_type:
            return False

        for field_name, expected in rule.match.items():
            actual = getattr(event, field_name, None)
            if not self._match_value(actual, expected):
                return False
        return True

    def _match_value(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, dict):
            if "contains" in expected:
                return str(expected["contains"]).lower() in str(actual or "").lower()
            if "regex" in expected:
                return re.search(str(expected["regex"]), str(actual or ""), re.IGNORECASE) is not None
        return str(actual) == str(expected)

    def _evaluate_aggregation_rule(self, event: LogEvent, rule: YAMLRule) -> Alert | None:
        aggregation = rule.aggregation or {}
        group_by_field = aggregation.get("group_by", "source_ip")
        group_by_value = getattr(event, group_by_field, None)
        if not group_by_value:
            return None

        window_seconds = int(aggregation.get("window_seconds", 60))
        threshold = int(aggregation.get("threshold", 1))
        function = aggregation.get("function", "count")
        field_name = aggregation.get("field")

        window = self._aggregations[rule.rule_id][str(group_by_value)]
        event_payload = event.to_dict()
        window.append((event.timestamp, event_payload))

        cutoff = event.timestamp - timedelta(seconds=window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

        current_value = self._aggregation_value(window, function, field_name)
        if current_value < threshold:
            return None

        bucket = int(event.timestamp.timestamp() // window_seconds)
        dedupe_key = (rule.rule_id, str(group_by_value), bucket)
        if dedupe_key in self._alerted_windows:
            return None

        self._alerted_windows.add(dedupe_key)
        return self._build_alert(event, rule, event_count=current_value)

    def _aggregation_value(
        self,
        window: deque[tuple[object, dict[str, Any]]],
        function: str,
        field_name: str | None,
    ) -> int:
        if function == "distinct_count" and field_name:
            return len(
                {
                    payload.get(field_name)
                    for _, payload in window
                    if payload.get(field_name) is not None
                }
            )
        return len(window)

    def _build_alert(self, event: LogEvent, rule: YAMLRule, event_count: int) -> Alert:
        return Alert(
            detector=self.name,
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            source_type=event.source_type,
            source_ip=event.source_ip,
            event_count=event_count,
            evidence=[event.to_dict()],
            metadata={
                "rule_id": rule.rule_id,
                "country": event.country,
                "risk_score": event.risk_score,
                "threat_labels": event.threat_labels,
            },
        )
