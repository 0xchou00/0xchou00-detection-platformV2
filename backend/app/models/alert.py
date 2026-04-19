from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass(slots=True)
class Alert:
    detector: str
    severity: str
    title: str
    description: str
    source_type: str
    source_ip: str | None
    event_count: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    evidence: list[dict] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["created_at"] = self.created_at.astimezone(timezone.utc).isoformat()
        return data
