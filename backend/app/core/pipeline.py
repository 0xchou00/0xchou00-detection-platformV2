from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import PipelineConfig
from app.detection.engine import DetectionEngine
from app.enrichment.ip_enricher import IPEnrichmentService
from app.ingestion.normalizer import LogNormalizer
from app.models.alert import Alert
from app.models.event import LogEvent
from app.storage.sqlite import SQLiteStorage


@dataclass(slots=True)
class PipelineResult:
    event: LogEvent | None
    alerts: list[Alert] = field(default_factory=list)


class ProcessingPipeline:
    """Normalize raw input, enrich the event, then evaluate detection logic."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        storage: SQLiteStorage | None = None,
    ) -> None:
        self.config = config or PipelineConfig()
        self.storage = storage or SQLiteStorage()
        self.normalizer = LogNormalizer()
        self.enrichment = IPEnrichmentService(self.storage, self.config.enrichment)
        self.engine = DetectionEngine(self.config)

    def process_line(self, raw_line: str, source_type: str) -> PipelineResult:
        event = self.normalizer.normalize(raw_line=raw_line, source_type=source_type)
        if event is None:
            return PipelineResult(event=None, alerts=[])

        enriched_event = self.enrichment.enrich(event)
        alerts = self.engine.process(enriched_event)
        return PipelineResult(event=enriched_event, alerts=alerts)
