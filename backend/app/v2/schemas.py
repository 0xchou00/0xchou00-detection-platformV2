from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    source_type: str = Field(..., examples=["ssh", "nginx", "firewall"])
    lines: list[str] = Field(default_factory=list)
    agent_id: str | None = None


class IngestResponse(BaseModel):
    accepted: int
    queued: int
    stream: str
    agent_id: str


class PendingSummary(BaseModel):
    pending: int
    min_id: str | None = None
    max_id: str | None = None
    consumers: list[Any] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    events: int
    alerts: int
    failed_events: int
    ingest_audit_rejections: int
    ingest_stream_backlog: int
    dead_letter_count: int
    ingest_pending: PendingSummary
    alert_pending: PendingSummary


class AgentRotateResponse(BaseModel):
    agent_id: str
    credential_id: str
    key_version: int
    api_key: str
    signing_secret: str
    rotated_from: str | None = None
