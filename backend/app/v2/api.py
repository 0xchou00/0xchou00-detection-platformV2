from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from redis.asyncio import Redis

from app.v2.auth import AnalystAccess, ViewerAccess, validate_api_key_role
from app.v2.config import settings
from app.v2.integrity import IntegrityService
from app.v2.schemas import HealthResponse, IngestRequest, IngestResponse
from app.v2.services import QueryService


router = APIRouter()
query_service = QueryService()


def get_redis() -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)


@router.get("/health", response_model=HealthResponse, dependencies=[ViewerAccess])
async def health(redis_client: Redis = Depends(get_redis)) -> HealthResponse:
    try:
        payload = await query_service.health(redis_client)
    finally:
        await redis_client.aclose()
    return HealthResponse(**payload)


@router.post("/ingest", response_model=IngestResponse, dependencies=[AnalystAccess])
async def ingest(payload: IngestRequest, redis_client: Redis = Depends(get_redis)) -> IngestResponse:
    queued = 0
    now = datetime.now(timezone.utc).isoformat()
    for line in payload.lines:
        cleaned = line.strip()
        if not cleaned:
            continue
        await redis_client.xadd(
            settings.ingest_stream,
            {
                "source_type": payload.source_type.strip().lower(),
                "line": cleaned,
                "received_at": now,
                "agent_id": payload.agent_id or "unknown",
            },
            maxlen=settings.stream_maxlen,
            approximate=True,
        )
        queued += 1
    await redis_client.aclose()
    return IngestResponse(accepted=len(payload.lines), queued=queued, stream=settings.ingest_stream)


@router.get("/events", dependencies=[ViewerAccess])
async def events(
    limit: int = Query(default=200, ge=1, le=2000),
    source_type: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=10080),
):
    items = await query_service.list_events(
        limit=limit,
        source_type=source_type,
        event_type=event_type,
        source_ip=source_ip,
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/alerts", dependencies=[ViewerAccess])
async def alerts(
    limit: int = Query(default=200, ge=1, le=2000),
    severity: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    alert_kind: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=10080),
):
    items = await query_service.list_alerts(
        limit=limit,
        severity=severity,
        detector=detector,
        source_ip=source_ip,
        rule_id=rule_id,
        alert_kind=alert_kind,
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/correlations", dependencies=[ViewerAccess])
async def correlations(
    limit: int = Query(default=200, ge=1, le=2000),
    source_ip: str | None = Query(default=None),
    since_minutes: int | None = Query(default=1440, ge=1, le=10080),
):
    items = await query_service.list_alerts(
        limit=limit,
        severity=None,
        detector="correlation",
        source_ip=source_ip,
        rule_id=None,
        alert_kind="correlation",
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/integrity/verify", dependencies=[ViewerAccess])
async def verify_integrity(limit: int = Query(default=50000, ge=1, le=500000)):
    return await IntegrityService().verify(limit=limit)


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    api_key = websocket.query_params.get("api_key")
    context = await validate_api_key_role(api_key, "viewer")
    if context is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(settings.live_channel)
    heartbeat = asyncio.create_task(_heartbeat(websocket))
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=2.0)
            if message and isinstance(message, dict):
                await websocket.send_text(message["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        heartbeat.cancel()
        await pubsub.unsubscribe(settings.live_channel)
        await pubsub.aclose()
        await redis_client.aclose()


async def _heartbeat(websocket: WebSocket) -> None:
    while True:
        await asyncio.sleep(15)
        await websocket.send_text(json.dumps({"kind": "heartbeat"}))
