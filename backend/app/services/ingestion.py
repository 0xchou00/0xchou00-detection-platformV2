from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from app.core.config import PipelineConfig
from app.core.pipeline import ProcessingPipeline
from app.services.correlation import CorrelationService
from app.services.integrity import IntegrityService
from app.storage.sqlite import SQLiteStorage


@dataclass(slots=True)
class IngestionSummary:
    accepted: int
    parsed: int
    alerts: int
    alert_items: list[dict]


@lru_cache(maxsize=1)
def _default_config() -> PipelineConfig:
    return PipelineConfig()


@lru_cache(maxsize=1)
def _default_storage() -> SQLiteStorage:
    return SQLiteStorage()


@lru_cache(maxsize=1)
def _default_pipeline() -> ProcessingPipeline:
    config = _default_config()
    storage = _default_storage()
    return ProcessingPipeline(config=config, storage=storage)


@lru_cache(maxsize=1)
def _default_integrity() -> IntegrityService:
    return IntegrityService(_default_storage())


@lru_cache(maxsize=1)
def _default_correlation() -> CorrelationService:
    config = _default_config()
    storage = _default_storage()
    return CorrelationService(storage, config.correlation)


class IngestionService:
    """Persist normalized events, detector alerts, and correlated alerts."""

    VALID_SOURCE_TYPES = {"ssh", "apache", "nginx", "web", "firewall", "network"}

    def __init__(
        self,
        pipeline: ProcessingPipeline | None = None,
        storage: SQLiteStorage | None = None,
        integrity: IntegrityService | None = None,
        correlation: CorrelationService | None = None,
        config: PipelineConfig | None = None,
    ) -> None:
        if any(item is not None for item in (pipeline, storage, integrity, correlation, config)):
            self.config = config or PipelineConfig()
            self.storage = storage or SQLiteStorage()
            self.pipeline = pipeline or ProcessingPipeline(config=self.config, storage=self.storage)
            self.integrity = integrity or IntegrityService(self.storage)
            self.correlation = correlation or CorrelationService(self.storage, self.config.correlation)
            return

        self.config = _default_config()
        self.storage = _default_storage()
        self.pipeline = _default_pipeline()
        self.integrity = _default_integrity()
        self.correlation = _default_correlation()

    def ingest_lines(self, lines: list[str], source_type: str) -> IngestionSummary:
        normalized_source_type = source_type.strip().lower()
        if normalized_source_type not in self.VALID_SOURCE_TYPES:
            raise ValueError(
                f"Unsupported source_type '{source_type}'. "
                f"Expected one of: {sorted(self.VALID_SOURCE_TYPES)}"
            )

        accepted = 0
        parsed = 0
        alerts_created: list[dict] = []

        for raw_line in lines:
            if not isinstance(raw_line, str):
                continue
            line = raw_line.strip()
            if not line:
                continue

            accepted += 1
            result = self.pipeline.process_line(line, normalized_source_type)
            if result.event is None:
                continue

            parsed += 1
            event_id = self.storage.insert_event(result.event)
            self.integrity.record_log(event_id, result.event)

            detector_alerts = []
            for alert in result.alerts:
                alert.metadata.setdefault("related_log_ids", [event_id])
                self.storage.insert_alert(alert)
                self.integrity.record_alert(alert)
                detector_alerts.append(alert)
                alerts_created.append(alert.to_dict())

            for correlated_alert in self.correlation.correlate(detector_alerts):
                self.storage.insert_alert(correlated_alert)
                self.integrity.record_alert(correlated_alert)
                alerts_created.append(correlated_alert.to_dict())

        return IngestionSummary(
            accepted=accepted,
            parsed=parsed,
            alerts=len(alerts_created),
            alert_items=alerts_created,
        )
