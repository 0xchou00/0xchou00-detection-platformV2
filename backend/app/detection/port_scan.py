from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from app.core.config import PortScanConfig
from app.detection.base import BaseDetector
from app.models.alert import Alert
from app.models.event import LogEvent


class PortScanDetector(BaseDetector):
    name = "port_scan"

    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()
        self._windows: dict[str, deque[tuple[object, int]]] = defaultdict(deque)
        self._triggered_buckets: set[tuple[str, int]] = set()

    def process(self, event: LogEvent) -> list[Alert]:
        if event.source_type not in {"firewall", "network"}:
            return []
        if event.event_type != "network_connection_attempt" or not event.source_ip:
            return []
        if event.destination_port is None:
            return []

        window = self._windows[event.source_ip]
        window.append((event.timestamp, int(event.destination_port)))
        cutoff = event.timestamp - timedelta(seconds=self.config.window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

        distinct_ports = sorted({port for _, port in window})
        if len(distinct_ports) < self.config.distinct_port_threshold:
            return []

        bucket = int(event.timestamp.timestamp() // self.config.window_seconds)
        dedupe_key = (event.source_ip, bucket)
        if dedupe_key in self._triggered_buckets:
            return []
        self._triggered_buckets.add(dedupe_key)

        severity = "critical" if (event.risk_score or 0) >= 80 else "high"
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="Port scan suspected",
                description=(
                    f"Source {event.source_ip} touched {len(distinct_ports)} destination ports "
                    f"within {self.config.window_seconds} seconds."
                ),
                source_type=event.source_type,
                source_ip=event.source_ip,
                event_count=len(distinct_ports),
                evidence=[event.to_dict()],
                metadata={
                    "distinct_ports": distinct_ports,
                    "window_seconds": self.config.window_seconds,
                    "destination_ip": event.destination_ip,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def reset(self) -> None:
        self._windows.clear()
        self._triggered_buckets.clear()
