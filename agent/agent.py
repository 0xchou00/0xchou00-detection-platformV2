from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml


@dataclass(slots=True)
class SourceConfig:
    source_type: str
    path: Path
    start_at_end: bool = True


@dataclass(slots=True)
class AgentConfig:
    api_url: str
    api_key: str
    max_lines: int
    flush_interval_seconds: float
    poll_interval_seconds: float
    state_file: Path
    sources: list[SourceConfig]


class OffsetTrackingTailer:
    """Track inode and byte offsets so tailing survives restarts and rotations."""

    def __init__(
        self,
        source_type: str,
        file_path: Path,
        state: dict[str, Any],
        *,
        start_at_end: bool,
    ) -> None:
        self.source_type = source_type
        self.file_path = file_path
        self._state = state
        self.start_at_end = start_at_end
        self._handle = None
        self._inode: int | None = None
        self._offset = 0

    def poll(self) -> list[str]:
        if not self.file_path.exists():
            self._close()
            return []

        stat = self.file_path.stat()
        inode = getattr(stat, "st_ino", None)
        saved = self._state.get(str(self.file_path), {})

        if self._handle is None or inode != self._inode:
            self._open_handle(saved, stat, inode)

        lines: list[str] = []
        while True:
            line = self._handle.readline()
            if not line:
                break
            self._offset = self._handle.tell()
            cleaned = line.rstrip("\n")
            if cleaned:
                lines.append(cleaned)

        self._sync_state()
        return lines

    def _open_handle(self, saved: dict[str, Any], stat, inode: int | None) -> None:
        self._close()
        self._handle = self.file_path.open("r", encoding="utf-8", errors="replace")
        self._inode = inode

        start_offset = 0
        if saved and saved.get("inode") == inode:
            start_offset = min(int(saved.get("offset", 0)), stat.st_size)
        elif self.start_at_end:
            start_offset = stat.st_size

        self._handle.seek(start_offset)
        self._offset = start_offset
        self._sync_state()

    def _sync_state(self) -> None:
        self._state[str(self.file_path)] = {
            "source_type": self.source_type,
            "inode": self._inode,
            "offset": self._offset,
        }

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self._inode = None


class IngestionAgent:
    """Batch tailed log lines and forward them to the detection tool API."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load_state()
        self._tailers = [
            OffsetTrackingTailer(
                source_type=source.source_type,
                file_path=source.path,
                state=self._state,
                start_at_end=source.start_at_end,
            )
            for source in self.config.sources
        ]
        self._buffers: dict[str, list[str]] = defaultdict(list)
        self._last_flush_at = time.monotonic()

    def run(self) -> None:
        while True:
            for tailer in self._tailers:
                self._buffers[tailer.source_type].extend(tailer.poll())

            if self._should_flush():
                self._flush_buffers()

            self._save_state()
            time.sleep(self.config.poll_interval_seconds)

    def _should_flush(self) -> bool:
        if any(len(lines) >= self.config.max_lines for lines in self._buffers.values()):
            return True
        return (time.monotonic() - self._last_flush_at) >= self.config.flush_interval_seconds

    def _flush_buffers(self) -> None:
        pending = {source_type: list(lines) for source_type, lines in self._buffers.items() if lines}
        if not pending:
            self._last_flush_at = time.monotonic()
            return

        for source_type, lines in pending.items():
            if self._send_batch(source_type, lines):
                self._buffers[source_type].clear()

        self._last_flush_at = time.monotonic()
        self._save_state()

    def _send_batch(self, source_type: str, lines: list[str]) -> bool:
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    self.config.api_url,
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key": self.config.api_key,
                    },
                    json={"source_type": source_type, "lines": lines},
                )
                response.raise_for_status()
        except Exception:
            return False
        return True

    def _load_state(self) -> dict[str, Any]:
        if not self.config.state_file.exists():
            return {}
        try:
            return json.loads(self.config.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self) -> None:
        self.config.state_file.write_text(
            json.dumps(self._state, indent=2, sort_keys=True),
            encoding="utf-8",
        )


def load_config(path: Path) -> AgentConfig:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    api = payload.get("api", {})
    batch = payload.get("batch", {})
    tail = payload.get("tail", {})
    sources = [
        SourceConfig(
            source_type=item["source_type"],
            path=Path(item["path"]),
            start_at_end=bool(item.get("start_at_end", True)),
        )
        for item in payload.get("sources", [])
        if isinstance(item, dict) and item.get("source_type") and item.get("path")
    ]

    state_file = Path(payload.get("state_file", "./agent/state.json"))
    if not state_file.is_absolute():
        state_file = (path.parent / state_file).resolve()

    return AgentConfig(
        api_url=api["url"],
        api_key=api["api_key"],
        max_lines=int(batch.get("max_lines", 25)),
        flush_interval_seconds=float(batch.get("flush_interval_seconds", 3)),
        poll_interval_seconds=float(tail.get("poll_interval_seconds", 0.5)),
        state_file=state_file,
        sources=sources,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="0xchou00 log ingestion agent")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).resolve().parent / "config.yaml"),
        help="Path to the agent YAML configuration file.",
    )
    args = parser.parse_args()

    config = load_config(Path(args.config).resolve())
    agent = IngestionAgent(config)
    agent.run()


if __name__ == "__main__":
    main()
