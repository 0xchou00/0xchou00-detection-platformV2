from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

ENV_PATTERN = re.compile(r"\$\{(?P<name>[A-Z0-9_]+)(?::-?(?P<default>[^}]*))?\}")


@dataclass(slots=True)
class SourceConfig:
    source_type: str
    path: Path
    start_at_end: bool = True


@dataclass(slots=True)
class AgentConfig:
    api_url: str
    api_key: str
    signing_secret: str
    key_version: int
    verify_tls: bool
    timeout_seconds: float
    max_lines_per_batch: int
    flush_interval_seconds: float
    poll_interval_seconds: float
    max_spool_items: int
    spool_file: Path
    state_file: Path
    retry_base_seconds: float
    retry_max_seconds: float
    retry_max_attempts: int
    agent_id: str
    sources: list[SourceConfig]


class OffsetTrackingTailer:
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
            self._open(saved, stat.st_size, inode)
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

    def _open(self, saved: dict[str, Any], file_size: int, inode: int | None) -> None:
        self._close()
        self._handle = self.file_path.open("r", encoding="utf-8", errors="replace")
        self._inode = inode
        if saved.get("inode") == inode:
            offset = min(int(saved.get("offset", 0)), file_size)
        else:
            offset = file_size if self.start_at_end else 0
        self._handle.seek(offset)
        self._offset = offset
        self._sync_state()

    def _sync_state(self) -> None:
        self._state[str(self.file_path)] = {
            "source_type": self.source_type,
            "inode": self._inode,
            "offset": self._offset,
            "updated_at": time.time(),
        }

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self._inode = None


class IngestionAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.spool_file.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load_json(self.config.state_file)
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
        self._retry_delay = self.config.retry_base_seconds

    async def run(self) -> None:
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds, verify=self.config.verify_tls) as client:
            while True:
                for tailer in self._tailers:
                    self._buffers[tailer.source_type].extend(tailer.poll())
                if self._should_flush():
                    await self._flush(client)
                self._save_json(self.config.state_file, self._state)
                await asyncio.sleep(self.config.poll_interval_seconds)

    def _should_flush(self) -> bool:
        if any(len(lines) >= self.config.max_lines_per_batch for lines in self._buffers.values()):
            return True
        return (time.monotonic() - self._last_flush_at) >= self.config.flush_interval_seconds

    async def _flush(self, client: httpx.AsyncClient) -> None:
        queued = self._load_spool()
        for source_type, lines in self._buffers.items():
            if lines:
                queued.append({"source_type": source_type, "lines": list(lines), "attempts": 0})
        self._buffers.clear()
        if not queued:
            self._last_flush_at = time.monotonic()
            return
        success_items: list[dict[str, Any]] = []
        for item in queued:
            ok = await self._send_batch(client, item["source_type"], item["lines"])
            if ok:
                success_items.append(item)
                self._retry_delay = self.config.retry_base_seconds
            else:
                item["attempts"] = int(item.get("attempts", 0)) + 1
                if self.config.retry_max_attempts and item["attempts"] > self.config.retry_max_attempts:
                    continue
        failed = [item for item in queued if item not in success_items][-self.config.max_spool_items :]
        self._save_spool(failed)
        if failed:
            await asyncio.sleep(self._retry_delay)
            self._retry_delay = min(self._retry_delay * 2, self.config.retry_max_seconds)
        self._last_flush_at = time.monotonic()

    async def _send_batch(self, client: httpx.AsyncClient, source_type: str, lines: list[str]) -> bool:
        if not lines:
            return True
        try:
            payload = {"source_type": source_type, "lines": lines, "agent_id": self.config.agent_id}
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            timestamp = int(time.time())
            nonce = secrets.token_urlsafe(16)
            signature = _build_signature(
                secret=self.config.signing_secret,
                body=body,
                agent_id=self.config.agent_id,
                nonce=nonce,
                timestamp=timestamp,
                key_version=self.config.key_version,
            )
            response = await client.post(
                self.config.api_url,
                headers={
                    "X-Agent-Id": self.config.agent_id,
                    "X-Agent-Key": self.config.api_key,
                    "X-Key-Version": str(self.config.key_version),
                    "X-Timestamp": str(timestamp),
                    "X-Nonce": nonce,
                    "X-Signature": signature,
                    "Content-Type": "application/json",
                },
                content=body,
            )
            response.raise_for_status()
            return True
        except Exception:
            return False

    def _load_spool(self) -> list[dict[str, Any]]:
        if not self.config.spool_file.exists():
            return []
        items: list[dict[str, Any]] = []
        for line in self.config.spool_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items[-self.config.max_spool_items :]

    def _save_spool(self, items: list[dict[str, Any]]) -> None:
        if not items:
            self.config.spool_file.write_text("", encoding="utf-8")
            return
        content = "\n".join(json.dumps(item, sort_keys=True) for item in items)
        self.config.spool_file.write_text(f"{content}\n", encoding="utf-8")

    def _load_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _resolve_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _resolve_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_env(item) for item in value]
    if not isinstance(value, str):
        return value

    def repl(match: re.Match[str]) -> str:
        name = match.group("name")
        default = match.group("default")
        return os.getenv(name, default or "")

    return ENV_PATTERN.sub(repl, value)


def load_config(path: Path) -> AgentConfig:
    payload = _resolve_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    api = payload.get("api", {})
    buffer_cfg = payload.get("buffer", {})
    retry_cfg = payload.get("retry", {})
    tail_cfg = payload.get("tail", {})
    sources = [
        SourceConfig(
            source_type=item["source_type"],
            path=Path(item["path"]),
            start_at_end=bool(item.get("start_at_end", True)),
        )
        for item in payload.get("sources", [])
        if isinstance(item, dict) and item.get("source_type") and item.get("path")
    ]
    state_file = Path(tail_cfg.get("state_file", "./state.json"))
    if not state_file.is_absolute():
        state_file = (path.parent / state_file).resolve()
    spool_file = Path(buffer_cfg.get("spool_file", "./spool.ndjson"))
    if not spool_file.is_absolute():
        spool_file = (path.parent / spool_file).resolve()

    return AgentConfig(
        api_url=str(api["url"]),
        api_key=str(api["api_key"]),
        signing_secret=str(api.get("signing_secret", "")),
        key_version=int(api.get("key_version", 1)),
        verify_tls=bool(api.get("verify_tls", False)),
        timeout_seconds=float(api.get("timeout_seconds", 8)),
        max_lines_per_batch=int(buffer_cfg.get("max_lines_per_batch", 200)),
        flush_interval_seconds=float(buffer_cfg.get("flush_interval_seconds", 2)),
        poll_interval_seconds=float(tail_cfg.get("poll_interval_seconds", 0.5)),
        max_spool_items=int(buffer_cfg.get("max_spool_items", 50000)),
        spool_file=spool_file,
        state_file=state_file,
        retry_base_seconds=float(retry_cfg.get("base_seconds", 1)),
        retry_max_seconds=float(retry_cfg.get("max_seconds", 30)),
        retry_max_attempts=int(retry_cfg.get("max_attempts", 0)),
        agent_id=str(payload.get("agent_id", "sensor-1")),
        sources=sources,
    )


def _build_signature(
    *,
    secret: str,
    body: bytes,
    agent_id: str,
    nonce: str,
    timestamp: int,
    key_version: int,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    material = "\n".join([agent_id, str(timestamp), nonce, str(key_version), body_hash])
    return hmac.new(secret.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="0xchou00 v2 ingestion agent")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "config.yaml"))
    args = parser.parse_args()
    config = load_config(Path(args.config).resolve())
    asyncio.run(IngestionAgent(config).run())


if __name__ == "__main__":
    main()
