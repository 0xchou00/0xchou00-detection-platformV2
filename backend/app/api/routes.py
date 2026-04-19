from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, status

from app.api.integrity import router as integrity_router
from app.api.schemas import HealthResponse, IngestRequest, IngestResponse
from app.security.rbac import AnalystAccess, ViewerAccess
from app.services.ingestion import IngestionService
from app.storage.sqlite import SQLiteStorage


router = APIRouter()
router.include_router(integrity_router)


def _since_timestamp(since_minutes: int | None) -> str | None:
    if since_minutes is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    storage = SQLiteStorage()
    counts = storage.get_counts()
    return HealthResponse(status="ok", logs=counts["logs"], alerts=counts["alerts"])


@router.post("/ingest", response_model=IngestResponse, dependencies=[AnalystAccess])
def ingest(payload: IngestRequest) -> IngestResponse:
    service = IngestionService()
    try:
        summary = service.ingest_lines(lines=payload.lines, source_type=payload.source_type)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return IngestResponse(
        accepted=summary.accepted,
        parsed=summary.parsed,
        alerts=summary.alerts,
        alert_items=summary.alert_items,
    )


@router.get("/alerts", dependencies=[ViewerAccess])
def list_alerts(
    limit: int = Query(default=100, ge=1, le=500),
    severity: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=1440),
):
    storage = SQLiteStorage()
    items = storage.list_alerts(
        limit=limit,
        severity=severity,
        detector=detector,
        source_type=source_type,
        since=_since_timestamp(since_minutes),
    )
    return {"items": items, "count": len(items)}


@router.get("/logs", dependencies=[ViewerAccess])
def list_logs(
    limit: int = Query(default=100, ge=1, le=500),
    source_type: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=1440),
):
    storage = SQLiteStorage()
    items = storage.list_logs(
        limit=limit,
        source_type=source_type,
        event_type=event_type,
        since=_since_timestamp(since_minutes),
    )
    return {"items": items, "count": len(items)}
