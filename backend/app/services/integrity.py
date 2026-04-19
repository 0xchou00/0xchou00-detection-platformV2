from __future__ import annotations

from app.models.alert import Alert
from app.models.event import LogEvent
from app.storage.sqlite import SQLiteStorage


class IntegrityService:
    """Persist a verifiable contract chain across logs and alerts."""

    def __init__(self, storage: SQLiteStorage | None = None) -> None:
        self.storage = storage or SQLiteStorage()

    def record_log(self, event_id: int, event: LogEvent) -> dict:
        return self.storage.append_chain_entry(
            entity_type="log",
            entity_id=str(event_id),
            payload=event.to_dict(),
            related_entities=[],
        )

    def record_alert(self, alert: Alert) -> dict:
        metadata = alert.metadata or {}
        related_entities = [
            {"entity_type": "log", "entity_id": str(log_id)}
            for log_id in metadata.get("related_log_ids", [])
        ] + [
            {"entity_type": "alert", "entity_id": str(alert_id)}
            for alert_id in metadata.get("matched_alert_ids", [])
        ]

        return self.storage.append_chain_entry(
            entity_type="alert",
            entity_id=alert.alert_id,
            payload=alert.to_dict(),
            related_entities=related_entities,
        )

    def verify(self) -> dict:
        return self.storage.verify_chain()
