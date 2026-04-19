from __future__ import annotations

import re
from datetime import datetime, timezone

from app.models.event import LogEvent


_SSH_FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>sshd)\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>sshd)\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_WEB_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/\d\.\d"\s+'
    r"(?P<status>\d{3})\s+\d+\s+"
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_FIREWALL_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>kernel|ufw)(?:\[\d+\])?:\s+"
    r"(?:\[UFW BLOCK\]\s+)?"
    r".*SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*"
    r"DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3}).*"
    r"PROTO=(?P<proto>[A-Z]+).*"
    r"DPT=(?P<dpt>\d+)"
)
_YEARLESS_SYSLOG_FORMAT = "%b %d %H:%M:%S"
_WEB_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogNormalizer:
    """Normalize multiple raw log formats into one event schema."""

    def normalize(self, raw_line: str, source_type: str) -> LogEvent | None:
        if source_type == "ssh":
            return self._parse_ssh(raw_line)
        if source_type in {"apache", "nginx", "web"}:
            return self._parse_web(raw_line, source_type)
        if source_type in {"firewall", "network"}:
            return self._parse_firewall(raw_line, source_type)
        return None

    def _parse_ssh(self, raw_line: str) -> LogEvent | None:
        failed_match = _SSH_FAILED_RE.match(raw_line)
        if failed_match:
            return LogEvent(
                timestamp=self._parse_yearless_syslog_ts(failed_match.group("ts")),
                source_type="ssh",
                raw_message=raw_line,
                event_type="authentication_failure",
                source_ip=failed_match.group("ip"),
                hostname=failed_match.group("host"),
                username=failed_match.group("user"),
                process=failed_match.group("process"),
                status="failed",
                severity="warning",
            )

        accepted_match = _SSH_ACCEPTED_RE.match(raw_line)
        if accepted_match:
            return LogEvent(
                timestamp=self._parse_yearless_syslog_ts(accepted_match.group("ts")),
                source_type="ssh",
                raw_message=raw_line,
                event_type="authentication_success",
                source_ip=accepted_match.group("ip"),
                hostname=accepted_match.group("host"),
                username=accepted_match.group("user"),
                process=accepted_match.group("process"),
                status="accepted",
                severity="info",
            )

        return None

    def _parse_web(self, raw_line: str, source_type: str) -> LogEvent | None:
        match = _WEB_RE.match(raw_line)
        if not match:
            return None

        status_code = int(match.group("status"))
        severity = "warning" if status_code >= 400 else "info"
        return LogEvent(
            timestamp=datetime.strptime(match.group("ts"), _WEB_TS_FORMAT).astimezone(timezone.utc),
            source_type=source_type,
            raw_message=raw_line,
            event_type="http_request",
            source_ip=match.group("ip"),
            status=str(status_code),
            severity=severity,
            http_method=match.group("method"),
            http_path=match.group("path"),
            http_status=status_code,
            http_user_agent=match.group("ua"),
            protocol="HTTP",
        )

    def _parse_firewall(self, raw_line: str, source_type: str) -> LogEvent | None:
        match = _FIREWALL_RE.match(raw_line)
        if not match:
            return None

        return LogEvent(
            timestamp=self._parse_yearless_syslog_ts(match.group("ts")),
            source_type=source_type,
            raw_message=raw_line,
            event_type="network_connection_attempt",
            source_ip=match.group("src"),
            destination_ip=match.group("dst"),
            destination_port=int(match.group("dpt")),
            hostname=match.group("host"),
            process=match.group("process"),
            protocol=match.group("proto"),
            status="blocked",
            severity="warning",
        )

    def _parse_yearless_syslog_ts(self, raw_ts: str) -> datetime:
        parsed = datetime.strptime(raw_ts, _YEARLESS_SYSLOG_FORMAT)
        now = datetime.now(timezone.utc)
        return parsed.replace(year=now.year, tzinfo=timezone.utc)
