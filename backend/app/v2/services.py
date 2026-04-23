from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from redis.asyncio import Redis
from sqlalchemy import func, select

from app.v2.config import settings
from app.v2.correlation import CorrelationEngine
from app.v2.db import AlertRecord, EventRecord, session_maker
from app.v2.detection import Alert, DetectionEngine, hash_payload
from app.v2.integrity import IntegrityService
from app.v2.normalizer import NormalizedEvent, Normalizer


class QueryService:
    async def health(self, redis_client: Redis) -> dict[str, Any]:
        async with session_maker() as session:
            event_count = await session.scalar(select(func.count()).select_from(EventRecord))
            alert_count = await session.scalar(select(func.count()).select_from(AlertRecord))
        backlog = await redis_client.xlen(settings.ingest_stream)
        return {
            "status": "ok",
            "events": int(event_count or 0),
            "alerts": int(alert_count or 0),
            "ingest_stream_backlog": int(backlog),
        }

    async def list_events(
        self,
        *,
        limit: int,
        source_type: str | None,
        event_type: str | None,
        source_ip: str | None,
        since_minutes: int | None,
    ) -> list[dict[str, Any]]:
        async with session_maker() as session:
            query = select(EventRecord).order_by(EventRecord.received_at.desc()).limit(limit)
            if source_type:
                query = query.where(EventRecord.source_type == source_type)
            if event_type:
                query = query.where(EventRecord.event_type == event_type)
            if source_ip:
                query = query.where(EventRecord.source_ip == source_ip)
            if since_minutes:
                query = query.where(
                    EventRecord.received_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
                )
            rows = (await session.execute(query)).scalars().all()
            return [self._event_dict(row) for row in rows]

    async def list_alerts(
        self,
        *,
        limit: int,
        severity: str | None,
        detector: str | None,
        source_ip: str | None,
        rule_id: str | None,
        alert_kind: str | None,
        since_minutes: int | None,
    ) -> list[dict[str, Any]]:
        async with session_maker() as session:
            query = select(AlertRecord).order_by(AlertRecord.created_at.desc()).limit(limit)
            if severity:
                query = query.where(AlertRecord.severity == severity)
            if detector:
                query = query.where(AlertRecord.detector == detector)
            if source_ip:
                query = query.where(AlertRecord.source_ip == source_ip)
            if rule_id:
                query = query.where(AlertRecord.rule_id == rule_id)
            if alert_kind:
                query = query.where(AlertRecord.alert_kind == alert_kind)
            if since_minutes:
                query = query.where(
                    AlertRecord.created_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
                )
            rows = (await session.execute(query)).scalars().all()
            return [self._alert_dict(row) for row in rows]

    def _event_dict(self, row: EventRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "timestamp": row.timestamp.isoformat(),
            "received_at": row.received_at.isoformat(),
            "source_type": row.source_type,
            "event_type": row.event_type,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "destination_port": row.destination_port,
            "severity": row.severity,
            "raw_message": row.raw_message,
            "payload": row.payload,
            "integrity_hash": row.integrity_hash,
        }

    def _alert_dict(self, row: AlertRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "created_at": row.created_at.isoformat(),
            "detector": row.detector,
            "rule_id": row.rule_id,
            "alert_kind": row.alert_kind,
            "severity": row.severity,
            "title": row.title,
            "description": row.description,
            "source_type": row.source_type,
            "source_ip": row.source_ip,
            "event_count": row.event_count,
            "metadata": row.metadata,
            "evidence": row.evidence,
            "integrity_hash": row.integrity_hash,
        }


class WorkerPipeline:
    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client
        self.normalizer = Normalizer()
        self.detector = DetectionEngine(redis_client, settings.yaml_rules_path)
        self.correlator = CorrelationEngine(redis_client, settings.correlation_rules_path)
        self.integrity = IntegrityService()

    async def process(self, source_type: str, line: str, received_at: str) -> None:
        event = self.normalizer.normalize(source_type, line)
        if event is None:
            return
        event_id = await self._store_event(event, received_at)
        detector_alerts = await self.detector.run(event)
        for alert in detector_alerts:
            await self._store_alert(alert, related_event_ids=[event_id])
            correlated = await self.correlator.run(alert)
            for corr in correlated:
                await self._store_alert(corr, related_event_ids=[event_id], related_alert_ids=[alert.alert_id])

    async def _store_event(self, event: NormalizedEvent, received_at: str) -> int:
        payload = event.to_payload()
        integrity_hash = hash_payload(payload)
        dt_received = datetime.fromisoformat(received_at)
        async with session_maker() as session:
            row = EventRecord(
                timestamp=event.timestamp,
                received_at=dt_received,
                source_type=event.source_type,
                event_type=event.event_type,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                severity=event.severity,
                raw_message=event.raw_message,
                payload=payload,
                integrity_hash=integrity_hash,
            )
            session.add(row)
            await session.flush()
            event_id = row.id
            await session.commit()

        await self.integrity.append(entity_type="event", entity_id=str(event_id), payload=payload, related_hashes=[])
        await self.redis.publish(
            settings.live_channel,
            json.dumps({"kind": "event", "payload": {"id": event_id, **payload}}, default=str),
        )
        return int(event_id)

    async def _store_alert(
        self,
        alert: Alert,
        *,
        related_event_ids: list[int],
        related_alert_ids: list[str] | None = None,
    ) -> None:
        payload = alert.to_dict()
        payload["metadata"] = {
            **payload.get("metadata", {}),
            "related_event_ids": related_event_ids,
            "related_alert_ids": related_alert_ids or [],
        }
        integrity_hash = hash_payload(payload)
        async with session_maker() as session:
            session.add(
                AlertRecord(
                    id=alert.alert_id,
                    created_at=alert.created_at,
                    detector=alert.detector,
                    rule_id=alert.rule_id,
                    alert_kind=alert.alert_kind,
                    severity=alert.severity,
                    title=alert.title,
                    description=alert.description,
                    source_type=alert.source_type,
                    source_ip=alert.source_ip,
                    event_count=alert.event_count,
                    metadata=payload["metadata"],
                    evidence=alert.evidence,
                    integrity_hash=integrity_hash,
                )
            )
            await session.commit()

        chain_hash = await self.integrity.append(
            entity_type="alert",
            entity_id=alert.alert_id,
            payload=payload,
            related_hashes=[str(event_id) for event_id in related_event_ids] + (related_alert_ids or []),
        )
        payload["integrity_chain_hash"] = chain_hash
        await self.redis.publish(settings.live_channel, json.dumps({"kind": "alert", "payload": payload}, default=str))
        await self.redis.xadd(
            settings.alert_stream,
            {"alert": json.dumps(payload, default=str)},
            maxlen=settings.stream_maxlen,
            approximate=True,
        )


class AlertDispatcher:
    async def deliver(self, payload: dict[str, Any]) -> None:
        severity = str(payload.get("severity", "medium")).lower()
        if severity in {"critical", "high"}:
            await self._send_webhook(payload, severity)
            await self._send_email(payload, severity)

    async def _send_webhook(self, payload: dict[str, Any], severity: str) -> None:
        url = settings.webhook_url_critical if severity == "critical" else settings.webhook_url_high
        if not url:
            return
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(url, json={"text": self._render_message(payload)})
            response.raise_for_status()

    async def _send_email(self, payload: dict[str, Any], severity: str) -> None:
        import smtplib
        from email.message import EmailMessage

        if not settings.smtp_host:
            return

        recipients = settings.smtp_recipients_critical if severity == "critical" else settings.smtp_recipients_high
        if not recipients:
            return

        message = EmailMessage()
        message["Subject"] = f"[{severity.upper()}] {payload.get('title', 'Detection Alert')}"
        message["From"] = settings.smtp_sender
        message["To"] = ", ".join(recipients)
        message.set_content(self._render_message(payload))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_tls:
                smtp.starttls()
            if settings.smtp_user and settings.smtp_password:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)

    def _render_message(self, payload: dict[str, Any]) -> str:
        return (
            f"Alert: {payload.get('title')}\n"
            f"Severity: {payload.get('severity')}\n"
            f"Detector: {payload.get('detector')}\n"
            f"Rule: {payload.get('rule_id')}\n"
            f"Source IP: {payload.get('source_ip')}\n"
            f"Description: {payload.get('description')}\n"
        )

