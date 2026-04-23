from __future__ import annotations

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    source_type: str = Field(..., examples=["ssh", "nginx", "firewall"])
    lines: list[str] = Field(default_factory=list)
    agent_id: str | None = None


class IngestResponse(BaseModel):
    accepted: int
    queued: int
    stream: str


class HealthResponse(BaseModel):
    status: str
    events: int
    alerts: int
    ingest_stream_backlog: int

