from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import select

from app.v2.auth import (
    AdminAccess,
    ViewerAccess,
    generate_agent_api_key,
    generate_agent_secret,
    validate_agent_ingest_request,
    validate_api_key_role,
)
from app.v2.config import settings
from app.v2.db import AgentCredentialRecord, session_maker
from app.v2.integrity import IntegrityService
from app.v2.redis_clients import pubsub_redis, state_redis, stream_redis
from app.v2.schemas import AgentRotateResponse, HealthResponse, IngestRequest, IngestResponse
from app.v2.services import QueryService


router = APIRouter()
query_service = QueryService()


def get_stream_redis() -> Redis:
    return stream_redis()


def get_state_redis() -> Redis:
    return state_redis()


def get_pubsub_redis() -> Redis:
    return pubsub_redis()


@router.get("/health", response_model=HealthResponse, dependencies=[ViewerAccess])
async def health(
    stream_client: Redis = Depends(get_stream_redis),
    state_client: Redis = Depends(get_state_redis),
) -> HealthResponse:
    try:
        payload = await query_service.health(stream_client=stream_client, state_client=state_client)
    finally:
        await stream_client.aclose()
        await state_client.aclose()
    return HealthResponse(**payload)


@router.post("/ingest", response_model=IngestResponse)
async def ingest(
    request: Request,
    stream_client: Redis = Depends(get_stream_redis),
    state_client: Redis = Depends(get_state_redis),
) -> IngestResponse:
    source_ip = _source_ip(request)
    body = await request.body()
    try:
        try:
            payload = IngestRequest.model_validate_json(body)
        except ValidationError as exc:
            await _record_ingest_audit_safe(
                agent_id=request.headers.get("X-Agent-Id"),
                source_ip=source_ip,
                outcome="rejected",
                reason="invalid_payload",
                details={"error": exc.errors()},
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid ingest payload.") from exc

        try:
            auth = await validate_agent_ingest_request(request=request, body=body, state_client=state_client)
        except HTTPException as exc:
            await _record_ingest_audit_safe(
                agent_id=request.headers.get("X-Agent-Id") or payload.agent_id,
                source_ip=source_ip,
                outcome="rejected",
                reason="authentication_failed",
                details={"detail": exc.detail, "source_type": payload.source_type, "line_count": len(payload.lines)},
            )
            raise

        if payload.agent_id and payload.agent_id != auth.agent_id:
            await _record_ingest_audit_safe(
                agent_id=auth.agent_id,
                source_ip=source_ip,
                outcome="rejected",
                reason="agent_identity_mismatch",
                details={"payload_agent_id": payload.agent_id},
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload agent_id does not match authenticated agent.")

        queued = 0
        now = _utcnow_iso()
        try:
            for line in payload.lines:
                cleaned = line.rstrip("\r\n")
                if cleaned == "":
                    continue
                await stream_client.xadd(
                    settings.ingest_stream,
                    {
                        "source_type": payload.source_type.strip().lower() or "unknown",
                        "line": cleaned,
                        "received_at": now,
                        "agent_id": auth.agent_id,
                        "ingest_source_ip": source_ip or "unknown",
                    },
                    maxlen=settings.stream_maxlen,
                    approximate=True,
                )
                queued += 1
        except Exception as exc:
            await _record_ingest_audit_safe(
                agent_id=auth.agent_id,
                source_ip=source_ip,
                outcome="rejected",
                reason="queue_error",
                details={"error": str(exc), "queued_before_failure": queued, "source_type": payload.source_type},
            )
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to enqueue ingest payload.") from exc

        await _record_ingest_audit_safe(
            agent_id=auth.agent_id,
            source_ip=source_ip,
            outcome="accepted",
            reason="queued",
            details={"source_type": payload.source_type, "accepted": len(payload.lines), "queued": queued},
        )
        return IngestResponse(
            accepted=len(payload.lines),
            queued=queued,
            stream=settings.ingest_stream,
            agent_id=auth.agent_id,
        )
    finally:
        await stream_client.aclose()
        await state_client.aclose()


@router.get("/events", dependencies=[ViewerAccess])
async def events(
    limit: int = Query(default=200, ge=1, le=2000),
    source_type: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    parser_status: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=10080),
):
    items = await query_service.list_events(
        limit=limit,
        source_type=source_type,
        event_type=event_type,
        source_ip=source_ip,
        parser_status=parser_status,
        agent_id=agent_id,
        search=search,
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
    search: str | None = Query(default=None),
    since_minutes: int | None = Query(default=None, ge=1, le=10080),
):
    items = await query_service.list_alerts(
        limit=limit,
        severity=severity,
        detector=detector,
        source_ip=source_ip,
        rule_id=rule_id,
        alert_kind=alert_kind,
        search=search,
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/correlations", dependencies=[ViewerAccess])
async def correlations(
    limit: int = Query(default=200, ge=1, le=2000),
    source_ip: str | None = Query(default=None),
    search: str | None = Query(default=None),
    since_minutes: int | None = Query(default=1440, ge=1, le=10080),
):
    items = await query_service.list_alerts(
        limit=limit,
        severity=None,
        detector="correlation",
        source_ip=source_ip,
        rule_id=None,
        alert_kind="correlation",
        search=search,
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/dead-letters", dependencies=[ViewerAccess])
async def dead_letters(
    limit: int = Query(default=100, ge=1, le=2000),
    stream_name: str | None = Query(default=None),
    stream_client: Redis = Depends(get_stream_redis),
    state_client: Redis = Depends(get_state_redis),
):
    try:
        items = await query_service.list_dead_letters(
            stream_client=stream_client,
            state_client=state_client,
            limit=limit,
            stream_name=stream_name,
        )
        return {"items": items, "count": len(items)}
    finally:
        await stream_client.aclose()
        await state_client.aclose()


@router.get("/ingest-audit", dependencies=[ViewerAccess])
async def ingest_audit(
    limit: int = Query(default=100, ge=1, le=2000),
    outcome: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    since_minutes: int | None = Query(default=1440, ge=1, le=10080),
):
    items = await query_service.list_ingest_audit(
        limit=limit,
        outcome=outcome,
        agent_id=agent_id,
        since_minutes=since_minutes,
    )
    return {"items": items, "count": len(items)}


@router.get("/integrity/verify", dependencies=[ViewerAccess])
async def verify_integrity(limit: int = Query(default=50000, ge=1, le=500000)):
    return await IntegrityService().verify(limit=limit)


@router.post("/admin/agents/{agent_id}/rotate", response_model=AgentRotateResponse, dependencies=[AdminAccess])
async def rotate_agent_key(agent_id: str):
    async with session_maker() as session:
        current = await session.scalar(
            select(AgentCredentialRecord).where(
                AgentCredentialRecord.agent_id == agent_id,
                AgentCredentialRecord.is_active.is_(True),
            )
        )
        if current is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")

        current.is_active = False
        new_record = AgentCredentialRecord(
            id=generate_agent_api_key(),
            agent_id=agent_id,
            name=current.name,
            api_key=generate_agent_api_key(),
            signing_secret=generate_agent_secret(),
            key_version=current.key_version + 1,
            rate_limit_per_window=current.rate_limit_per_window,
            is_active=True,
            rotated_from=current.id,
            created_at=datetime.now(timezone.utc),
        )
        session.add(new_record)
        await session.commit()
        return AgentRotateResponse(
            agent_id=agent_id,
            credential_id=new_record.id,
            key_version=new_record.key_version,
            api_key=new_record.api_key,
            signing_secret=new_record.signing_secret,
            rotated_from=current.id,
        )


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    api_key = websocket.query_params.get("api_key")
    context = await validate_api_key_role(api_key, "viewer")
    if context is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    redis_client = pubsub_redis()
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


def _source_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _record_ingest_audit_safe(
    *,
    agent_id: str | None,
    source_ip: str | None,
    outcome: str,
    reason: str,
    details: dict[str, object],
) -> None:
    try:
        await query_service.record_ingest_audit(
            agent_id=agent_id,
            source_ip=source_ip,
            outcome=outcome,
            reason=reason,
            details=details,
        )
    except Exception:
        return
