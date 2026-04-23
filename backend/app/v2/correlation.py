from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from app.v2.config import settings
from app.v2.detection import Alert
from app.v2.state import AbstractStateStore


class CorrelationStageModel(BaseModel):
    detector: str
    rule_id: str | None = None


class CorrelationRuleModel(BaseModel):
    id: str
    title: str
    description: str
    severity: str = "high"
    explanation: str
    detection_logic: str
    mitre_attack: list[str] = Field(default_factory=list)
    window_seconds: int = 600
    group_by: str = "source_ip"
    sequence: list[CorrelationStageModel]


@dataclass(slots=True)
class CorrelationRule:
    rule_id: str
    title: str
    description: str
    severity: str
    explanation: str
    detection_logic: str
    mitre_attack: list[str]
    window_seconds: int
    group_by: str
    sequence: list[CorrelationStageModel]


class CorrelationEngine:
    def __init__(self, state_store: AbstractStateStore, rules_path: Path) -> None:
        self.state = state_store
        self.rules_path = rules_path
        self._rules: list[CorrelationRule] = []
        self._mtime: float | None = None
        self._reload(force=True)

    async def run(self, alert: Alert) -> list[Alert]:
        self._reload()
        group = alert.source_ip
        if not group:
            return []

        history_key = f"siem:corr:history:{group}"
        score = int(alert.created_at.timestamp())
        await self.state.add_sorted_json(
            history_key,
            score,
            {
                "id": alert.alert_id,
                "detector": alert.detector,
                "rule_id": alert.rule_id,
                "severity": alert.severity,
                "title": alert.title,
                "created_at": alert.created_at.astimezone(timezone.utc).isoformat(),
            },
            settings.correlation_history_ttl_seconds,
        )

        history = await self.state.range_sorted_json(
            history_key,
            score - settings.correlation_history_ttl_seconds,
            score,
        )
        generated: list[Alert] = []
        for rule in self._rules:
            if not self._matches_sequence(history, rule, alert.created_at):
                continue
            fingerprint = self._fingerprint(rule.rule_id, group, alert.created_at, history)
            if not await self.state.dedupe(f"siem:corr:dedupe:{fingerprint}", rule.window_seconds):
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
                        "matched_sequence": [stage.detector for stage in rule.sequence],
                        "fingerprint": fingerprint,
                        "explanation": rule.explanation,
                        "detection_logic": rule.detection_logic,
                        "mitre_attack": rule.mitre_attack,
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
        current = self.rules_path.stat().st_mtime
        if not force and self._mtime == current:
            return
        payload = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        rules: list[CorrelationRule] = []
        for item in payload.get("rules", []):
            try:
                parsed = CorrelationRuleModel.model_validate(item)
            except ValidationError as exc:
                raise ValueError(f"Invalid correlation rule: {exc}") from exc
            rules.append(
                CorrelationRule(
                    rule_id=parsed.id,
                    title=parsed.title,
                    description=parsed.description,
                    severity=parsed.severity,
                    explanation=parsed.explanation,
                    detection_logic=parsed.detection_logic,
                    mitre_attack=list(parsed.mitre_attack),
                    window_seconds=parsed.window_seconds,
                    group_by=parsed.group_by,
                    sequence=list(parsed.sequence),
                )
            )
        self._rules = rules
        self._mtime = current

    def _matches_sequence(self, history: list[dict[str, Any]], rule: CorrelationRule, now: datetime) -> bool:
        window_floor = int(now.astimezone(timezone.utc).timestamp()) - rule.window_seconds
        bounded = [
            item for item in history if int(datetime.fromisoformat(item["created_at"]).timestamp()) >= window_floor
        ]
        index = 0
        for item in bounded:
            stage = rule.sequence[index]
            if item.get("detector") != stage.detector:
                continue
            if stage.rule_id and item.get("rule_id") != stage.rule_id:
                continue
            index += 1
            if index == len(rule.sequence):
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

