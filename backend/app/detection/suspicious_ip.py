from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from app.core.config import SuspiciousIPConfig
from app.detection.base import BaseDetector
from app.models.alert import Alert
from app.models.event import LogEvent


class SuspiciousIPDetector(BaseDetector):
    name = "suspicious_ip"

    def __init__(self, config: SuspiciousIPConfig | None = None) -> None:
        self.config = config or SuspiciousIPConfig()
        self._request_windows: dict[str, deque] = defaultdict(deque)
        self._status_windows: dict[str, deque] = defaultdict(deque)
        self._triggered_keys: set[tuple[str, str]] = set()

    def process(self, event: LogEvent) -> list[Alert]:
        if event.source_type not in {"apache", "nginx", "web"} or not event.source_ip:
            return []
        if event.event_type != "http_request":
            return []

        alerts: list[Alert] = []
        alerts.extend(self._evaluate_request_rate(event))
        alerts.extend(self._evaluate_error_ratio(event))
        alerts.extend(self._evaluate_sensitive_path(event))
        return alerts

    def reset(self) -> None:
        self._request_windows.clear()
        self._status_windows.clear()
        self._triggered_keys.clear()

    def _evaluate_request_rate(self, event: LogEvent) -> list[Alert]:
        window = self._request_windows[event.source_ip]
        window.append(event.timestamp)
        self._prune(window, event.timestamp, self.config.request_rate_window_seconds)
        count = len(window)

        if count < self.config.request_rate_threshold:
            self._triggered_keys.discard((event.source_ip, "request_rate"))
            return []

        key = (event.source_ip, "request_rate")
        if key in self._triggered_keys:
            return []

        self._triggered_keys.add(key)
        severity = "critical" if (event.risk_score or 0) >= 80 else "high"
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="Suspicious web request rate",
                description=(
                    f"Source {event.source_ip} generated {count} web requests within "
                    f"{self.config.request_rate_window_seconds} seconds."
                ),
                source_type=event.source_type,
                source_ip=event.source_ip,
                event_count=count,
                evidence=[event.to_dict()],
                metadata={
                    "reason": "request_rate",
                    "request_count": count,
                    "window_seconds": self.config.request_rate_window_seconds,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def _evaluate_error_ratio(self, event: LogEvent) -> list[Alert]:
        window = self._status_windows[event.source_ip]
        window.append((event.timestamp, event.http_status or 0))
        self._prune_statuses(window, event.timestamp, self.config.request_rate_window_seconds)

        total = len(window)
        errors = sum(1 for _, status in window if status >= 400)
        ratio = errors / total if total else 0.0

        if total < self.config.error_ratio_min_requests or ratio < self.config.error_ratio_threshold:
            self._triggered_keys.discard((event.source_ip, "error_ratio"))
            return []

        key = (event.source_ip, "error_ratio")
        if key in self._triggered_keys:
            return []

        self._triggered_keys.add(key)
        severity = "high" if (event.risk_score or 0) >= 60 else "medium"
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="Suspicious HTTP error ratio",
                description=(
                    f"Source {event.source_ip} produced {errors}/{total} HTTP error responses "
                    f"({ratio:.0%}) in the current analysis window."
                ),
                source_type=event.source_type,
                source_ip=event.source_ip,
                event_count=errors,
                evidence=[event.to_dict()],
                metadata={
                    "reason": "error_ratio",
                    "errors": errors,
                    "total_requests": total,
                    "error_ratio": ratio,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def _evaluate_sensitive_path(self, event: LogEvent) -> list[Alert]:
        path = (event.http_path or "").lower()
        if path not in self.config.sensitive_paths:
            return []

        key = (event.source_ip, f"sensitive:{path}")
        if key in self._triggered_keys:
            return []

        self._triggered_keys.add(key)
        severity = "high" if (event.risk_score or 0) >= 60 else "medium"
        return [
            Alert(
                detector=self.name,
                severity=severity,
                title="Sensitive path access attempt",
                description=f"Source {event.source_ip} requested a sensitive path: {event.http_path}.",
                source_type=event.source_type,
                source_ip=event.source_ip,
                evidence=[event.to_dict()],
                metadata={
                    "reason": "sensitive_path",
                    "path": event.http_path,
                    "status": event.http_status,
                    "user_agent": event.http_user_agent,
                    "country": event.country,
                    "risk_score": event.risk_score,
                    "threat_labels": event.threat_labels,
                },
            )
        ]

    def _prune(self, window: deque, current_ts, window_seconds: int) -> None:
        threshold = current_ts - timedelta(seconds=window_seconds)
        while window and window[0] < threshold:
            window.popleft()

    def _prune_statuses(self, window: deque, current_ts, window_seconds: int) -> None:
        threshold = current_ts - timedelta(seconds=window_seconds)
        while window and window[0][0] < threshold:
            window.popleft()
