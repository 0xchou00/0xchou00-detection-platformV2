from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


SSH_FAIL_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_OK_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
WEB_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/\d\.\d"\s+(?P<status>\d{3})\s+\d+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
FW_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3}).*PROTO=(?P<proto>[A-Z]+).*DPT=(?P<dpt>\d+)"
)

SYS_TS_FORMAT = "%b %d %H:%M:%S"
WEB_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime
    source_type: str
    event_type: str
    raw_message: str
    severity: str
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "source_type": self.source_type,
            "event_type": self.event_type,
            "raw_message": self.raw_message,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "metadata": self.metadata,
        }


class Normalizer:
    def normalize(self, source_type: str, line: str) -> NormalizedEvent | None:
        source = source_type.lower().strip()
        if source == "ssh":
            return self._parse_ssh(line)
        if source in {"nginx", "apache", "web"}:
            return self._parse_http(source, line)
        if source in {"firewall", "network"}:
            return self._parse_firewall(source, line)
        return None

    def _parse_ssh(self, line: str) -> NormalizedEvent | None:
        failed = SSH_FAIL_RE.match(line)
        if failed:
            return NormalizedEvent(
                timestamp=self._parse_sys_ts(failed.group("ts")),
                source_type="ssh",
                event_type="authentication_failure",
                raw_message=line,
                severity="high",
                source_ip=failed.group("ip"),
                metadata={"username": failed.group("user"), "status": "failed"},
            )
        accepted = SSH_OK_RE.match(line)
        if accepted:
            return NormalizedEvent(
                timestamp=self._parse_sys_ts(accepted.group("ts")),
                source_type="ssh",
                event_type="authentication_success",
                raw_message=line,
                severity="info",
                source_ip=accepted.group("ip"),
                metadata={"username": accepted.group("user"), "status": "success"},
            )
        return None

    def _parse_http(self, source: str, line: str) -> NormalizedEvent | None:
        match = WEB_RE.match(line)
        if not match:
            return None
        status_code = int(match.group("status"))
        severity = "medium" if status_code >= 400 else "info"
        return NormalizedEvent(
            timestamp=datetime.strptime(match.group("ts"), WEB_TS_FORMAT).astimezone(timezone.utc),
            source_type=source,
            event_type="http_request",
            raw_message=line,
            severity=severity,
            source_ip=match.group("ip"),
            metadata={
                "method": match.group("method"),
                "path": match.group("path"),
                "status": status_code,
                "user_agent": match.group("ua"),
            },
        )

    def _parse_firewall(self, source: str, line: str) -> NormalizedEvent | None:
        match = FW_RE.match(line)
        if not match:
            return None
        return NormalizedEvent(
            timestamp=self._parse_sys_ts(match.group("ts")),
            source_type=source,
            event_type="network_connection_attempt",
            raw_message=line,
            severity="medium",
            source_ip=match.group("src"),
            destination_ip=match.group("dst"),
            destination_port=int(match.group("dpt")),
            metadata={"protocol": match.group("proto"), "status": "blocked"},
        )

    def _parse_sys_ts(self, raw: str) -> datetime:
        parsed = datetime.strptime(raw, SYS_TS_FORMAT)
        now = datetime.now(timezone.utc)
        return parsed.replace(year=now.year, tzinfo=timezone.utc)

