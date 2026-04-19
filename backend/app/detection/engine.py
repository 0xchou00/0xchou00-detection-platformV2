from __future__ import annotations

from app.core.config import PipelineConfig
from app.detection.anomaly import FrequencyAnomalyDetector
from app.detection.base import BaseDetector
from app.detection.brute_force import BruteForceDetector
from app.detection.port_scan import PortScanDetector
from app.detection.suspicious_ip import SuspiciousIPDetector
from app.detection.yaml_rules import YAMLRuleDetector
from app.models.alert import Alert
from app.models.event import LogEvent


class DetectionEngine:
    """Run normalized events through the configured detector set."""

    def __init__(self, config: PipelineConfig | None = None) -> None:
        pipeline_config = config or PipelineConfig()
        self.detectors: list[BaseDetector] = [
            BruteForceDetector(pipeline_config.brute_force),
            SuspiciousIPDetector(pipeline_config.suspicious_ip),
            PortScanDetector(pipeline_config.port_scan),
            YAMLRuleDetector(pipeline_config.rules_file),
            FrequencyAnomalyDetector(
                window_seconds=pipeline_config.anomaly_window_seconds,
                baseline_windows=pipeline_config.anomaly_baseline_windows,
                min_events=pipeline_config.anomaly_min_events,
                spike_multiplier=pipeline_config.anomaly_spike_multiplier,
            ),
        ]

    def process(self, event: LogEvent) -> list[Alert]:
        alerts: list[Alert] = []
        for detector in self.detectors:
            alerts.extend(detector.process(event))
        return alerts

    def reset(self) -> None:
        for detector in self.detectors:
            detector.reset()
