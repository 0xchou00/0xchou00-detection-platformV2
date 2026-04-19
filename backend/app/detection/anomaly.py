from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from app.detection.base import BaseDetector
from app.models.alert import Alert
from app.models.event import LogEvent


@dataclass(slots=True)
class FrequencyWindowState:
    bucket_start: int | None = None
    current_count: int = 0
    history: deque[int] = field(default_factory=deque)


class FrequencyAnomalyDetector(BaseDetector):
    name = "anomaly_frequency"

    def __init__(
        self,
        *,
        window_seconds: int = 60,
        baseline_windows: int = 5,
        min_events: int = 12,
        spike_multiplier: float = 3.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.baseline_windows = baseline_windows
        self.min_events = min_events
        self.spike_multiplier = spike_multiplier
        self._states: dict[str, FrequencyWindowState] = defaultdict(
            lambda: FrequencyWindowState(history=deque(maxlen=self.baseline_windows))
        )
        self._alerted_buckets: set[tuple[str, int]] = set()

    def process(self, event: LogEvent) -> list[Alert]:
        if not event.source_ip:
            return []

        key = f"{event.source_type}:{event.source_ip}"
        bucket = int(event.timestamp.timestamp() // self.window_seconds)
        state = self._states[key]

        if state.bucket_start is None:
            state.bucket_start = bucket

        if bucket != state.bucket_start:
            state.history.append(state.current_count)
            state.current_count = 0
            state.bucket_start = bucket

        state.current_count += 1

        if len(state.history) < self.baseline_windows:
            return []

        baseline_average = sum(state.history) / len(state.history)
        threshold = max(self.min_events, baseline_average * self.spike_multiplier)
        dedupe_key = (key, bucket)
        if state.current_count < threshold or dedupe_key in self._alerted_buckets:
            return []

        self._alerted_buckets.add(dedupe_key)
        severity = "high" if (event.risk_score or 0) >= 70 else "medium"
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="Traffic spike anomaly",
                description=(
                    f"Observed {state.current_count} events from {event.source_ip} in the current "
                    f"{self.window_seconds}-second window against a baseline average of "
                    f"{baseline_average:.1f}."
                ),
                source_type=event.source_type,
                source_ip=event.source_ip,
                event_count=state.current_count,
                evidence=[event.to_dict()],
                metadata={
                    "baseline_average": round(baseline_average, 2),
                    "window_seconds": self.window_seconds,
                    "baseline_windows": self.baseline_windows,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def reset(self) -> None:
        self._states.clear()
        self._alerted_buckets.clear()
