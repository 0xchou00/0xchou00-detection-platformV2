from __future__ import annotations

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    source_type: str = Field(..., examples=["ssh", "nginx", "firewall"])
    lines: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    logs: int
    alerts: int


class IngestResponse(BaseModel):
    accepted: int
    parsed: int
    alerts: int
    alert_items: list[dict]
