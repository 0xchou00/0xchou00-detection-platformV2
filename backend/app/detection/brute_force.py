from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from app.core.config import BruteForceConfig
from app.detection.base import BaseDetector
from app.models.alert import Alert
from app.models.event import LogEvent


class BruteForceDetector(BaseDetector):
    name = "brute_force"

    def __init__(self, config: BruteForceConfig | None = None) -> None:
        self.config = config or BruteForceConfig()
        self._failures: dict[str, deque] = defaultdict(deque)
        self._last_alert_size: dict[str, int] = {}

    def process(self, event: LogEvent) -> list[Alert]:
        if event.source_type != "ssh":
            return []
        if event.event_type != "authentication_failure" or not event.source_ip:
            return []

        window = self._failures[event.source_ip]
        window.append(event.timestamp)
        self._expire_old(event.source_ip, event.timestamp)

        failure_count = len(window)
        if failure_count < self.config.failure_threshold:
            return []

        previous_count = self._last_alert_size.get(event.source_ip, 0)
        if failure_count == previous_count:
            return []

        self._last_alert_size[event.source_ip] = failure_count
        severity = self._severity_for(event, failure_count)
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="SSH brute force suspected",
                description=(
                    f"Observed {failure_count} failed SSH authentication attempts from "
                    f"{event.source_ip} inside {self.config.window_seconds} seconds."
                ),
                source_type=event.source_type,
                source_ip=event.source_ip,
                event_count=failure_count,
                evidence=[event.to_dict()],
                metadata={
                    "username": event.username,
                    "window_seconds": self.config.window_seconds,
                    "failure_count": failure_count,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def reset(self) -> None:
        self._failures.clear()
        self._last_alert_size.clear()

    def _expire_old(self, source_ip: str, current_ts) -> None:
        threshold = current_ts - timedelta(seconds=self.config.window_seconds)
        window = self._failures[source_ip]
        while window and window[0] < threshold:
            window.popleft()
        if not window:
            self._last_alert_size.pop(source_ip, None)

    def _severity_for(self, event: LogEvent, failure_count: int) -> str:
        if (event.risk_score or 0) >= 80:
            return "critical"
        if failure_count >= self.config.failure_threshold * self.config.critical_multiplier:
            return "critical"
        return "high"
