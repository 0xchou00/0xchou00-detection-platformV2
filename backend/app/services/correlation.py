from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from app.core.config import CorrelationConfig
from app.models.alert import Alert
from app.storage.sqlite import SQLiteStorage


@dataclass(slots=True)
class CorrelationSelector:
    detector: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CorrelationRule:
    rule_id: str
    title: str
    description: str
    severity: str
    time_window_seconds: int
    same_source_ip: bool = True
    alerts: list[CorrelationSelector] = field(default_factory=list)


class CorrelationService:
    """Promote multiple aligned detector signals into one higher-severity alert."""

    def __init__(
        self,
        storage: SQLiteStorage | None = None,
        config: CorrelationConfig | None = None,
    ) -> None:
        self.storage = storage or SQLiteStorage()
        self.config = config or CorrelationConfig()
        self.rules_file = Path(self.config.rules_file)
        self._rules: list[CorrelationRule] = []
        self._last_loaded_mtime: float | None = None
        self._load_rules()

    def correlate(self, new_alerts: list[Alert]) -> list[Alert]:
        correlated: list[Alert] = []
        if not new_alerts:
            return correlated

        self._reload_if_changed()
        for alert in new_alerts:
            for rule in self._rules:
                if not self._rule_mentions_detector(rule, alert.detector):
                    continue
                correlated_alert = self._evaluate_rule(alert, rule)
                if correlated_alert is not None:
                    correlated.append(correlated_alert)
        return correlated

    def _evaluate_rule(self, seed_alert: Alert, rule: CorrelationRule) -> Alert | None:
        since = (seed_alert.created_at - timedelta(seconds=rule.time_window_seconds)).isoformat()
        source_ip = seed_alert.source_ip if rule.same_source_ip else None
        recent_alerts = self.storage.list_alerts(
            limit=500,
            since=since,
            source_ip=source_ip,
            alert_kind="detection",
        )

        matched_items: list[dict[str, Any]] = []
        for selector in rule.alerts:
            candidate = self._match_selector(recent_alerts, selector)
            if candidate is None:
                return None
            matched_items.append(candidate)

        fingerprint = self._fingerprint(rule, seed_alert, matched_items)
        if self.storage.correlation_fingerprint_exists(fingerprint):
            return None

        source_types = {item["source_type"] for item in matched_items if item.get("source_type")}
        correlation_source_type = source_types.pop() if len(source_types) == 1 else "correlation"
        related_log_ids: list[int] = []
        for item in matched_items:
            metadata = item.get("metadata", {})
            for log_id in metadata.get("related_log_ids", []):
                if log_id not in related_log_ids:
                    related_log_ids.append(log_id)

        return Alert(
            detector="correlation",
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            source_type=correlation_source_type,
            source_ip=seed_alert.source_ip if rule.same_source_ip else None,
            event_count=len(matched_items),
            evidence=matched_items,
            metadata={
                "alert_kind": "correlation",
                "correlation_rule_id": rule.rule_id,
                "correlation_fingerprint": fingerprint,
                "matched_alert_ids": [item["id"] for item in matched_items],
                "matched_detectors": [item["detector"] for item in matched_items],
                "related_log_ids": related_log_ids,
                "time_window_seconds": rule.time_window_seconds,
                "same_source_ip": rule.same_source_ip,
            },
        )

    def _rule_mentions_detector(self, rule: CorrelationRule, detector: str) -> bool:
        return any(selector.detector == detector for selector in rule.alerts)

    def _match_selector(
        self,
        alerts: list[dict[str, Any]],
        selector: CorrelationSelector,
    ) -> dict[str, Any] | None:
        for item in alerts:
            if item.get("detector") != selector.detector:
                continue
            metadata = item.get("metadata", {})
            if not self._metadata_matches(metadata, selector.metadata):
                continue
            return item
        return None

    def _metadata_matches(self, metadata: dict[str, Any], expected: dict[str, Any]) -> bool:
        for key, value in expected.items():
            if metadata.get(key) != value:
                return False
        return True

    def _fingerprint(
        self,
        rule: CorrelationRule,
        seed_alert: Alert,
        matched_items: list[dict[str, Any]],
    ) -> str:
        bucket = int(seed_alert.created_at.timestamp() // rule.time_window_seconds)
        material = json.dumps(
            {
                "rule_id": rule.rule_id,
                "source_ip": seed_alert.source_ip,
                "bucket": bucket,
                "detectors": sorted(item["detector"] for item in matched_items),
            },
            sort_keys=True,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _reload_if_changed(self) -> None:
        if not self.rules_file.exists():
            return
        current_mtime = self.rules_file.stat().st_mtime
        if current_mtime != self._last_loaded_mtime:
            self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_file.exists():
            self._rules = []
            self._last_loaded_mtime = None
            return

        payload = yaml.safe_load(self.rules_file.read_text(encoding="utf-8")) or {}
        rules: list[CorrelationRule] = []
        for item in payload.get("rules", []):
            conditions = item.get("conditions", {})
            output = item.get("output", {})
            selectors = [
                CorrelationSelector(
                    detector=selector["detector"],
                    metadata=selector.get("metadata", {}),
                )
                for selector in conditions.get("alerts", [])
                if isinstance(selector, dict) and selector.get("detector")
            ]
            if not selectors:
                continue

            rules.append(
                CorrelationRule(
                    rule_id=item["id"],
                    title=output.get("title", item.get("title", item["id"])),
                    description=output.get("description", item.get("description", item["id"])),
                    severity=output.get("severity", item.get("severity", "high")),
                    time_window_seconds=int(conditions.get("time_window_seconds", 300)),
                    same_source_ip=bool(conditions.get("same_source_ip", True)),
                    alerts=selectors,
                )
            )

        self._rules = rules
        self._last_loaded_mtime = self.rules_file.stat().st_mtime
