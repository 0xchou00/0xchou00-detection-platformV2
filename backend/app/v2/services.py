from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from redis.asyncio import Redis
from sqlalchemy import func, or_, select

from app.v2.config import settings
from app.v2.correlation import CorrelationEngine
from app.v2.db import AlertRecord, EventRecord, IngestAuditRecord, session_maker
from app.v2.detection import Alert, DetectionEngine, hash_payload
from app.v2.enrichment import EnrichmentService
from app.v2.integrity import IntegrityService
from app.v2.normalizer import NormalizedEvent, Normalizer
from app.v2.state import AbstractStateStore
from app.v2.streaming import StreamReliabilityManager


LOGGER = logging.getLogger("siem-services")


class QueryService:
    async def health(self, *, stream_client: Redis, state_client: Redis) -> dict[str, Any]:
        async with session_maker() as session:
            event_count = await session.scalar(select(func.count()).select_from(EventRecord))
            alert_count = await session.scalar(select(func.count()).select_from(AlertRecord))
            failed_count = await session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.parser_status == "failed")
            )
            audit_failures = await session.scalar(
                select(func.count()).select_from(IngestAuditRecord).where(IngestAuditRecord.outcome == "rejected")
            )

        ingest_reliability = StreamReliabilityManager(
            stream_client,
            state_client,
            stream_name=settings.ingest_stream,
            group_name=settings.ingest_group,
            consumer_name=settings.worker_id,
        )
        alert_reliability = StreamReliabilityManager(
            stream_client,
            state_client,
            stream_name=settings.alert_stream,
            group_name=settings.alert_group,
            consumer_name=settings.alerter_id,
        )
        ingest_pending = await ingest_reliability.pending_summary()
        alert_pending = await alert_reliability.pending_summary()
        backlog = await stream_client.xlen(settings.ingest_stream)
        dead_letters = await ingest_reliability.dead_letter_count()
        return {
            "status": "ok",
            "events": int(event_count or 0),
            "alerts": int(alert_count or 0),
            "failed_events": int(failed_count or 0),
            "ingest_audit_rejections": int(audit_failures or 0),
            "ingest_stream_backlog": int(backlog),
            "dead_letter_count": int(dead_letters),
            "ingest_pending": ingest_pending,
            "alert_pending": alert_pending,
        }

    async def list_events(
        self,
        *,
        limit: int,
        source_type: str | None,
        event_type: str | None,
        source_ip: str | None,
        parser_status: str | None,
        agent_id: str | None,
        search: str | None,
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
            if parser_status:
                query = query.where(EventRecord.parser_status == parser_status)
            if agent_id:
                query = query.where(EventRecord.agent_id == agent_id)
            if search:
                query = query.where(
                    or_(
                        EventRecord.raw_message.ilike(f"%{search}%"),
                        EventRecord.event_type.ilike(f"%{search}%"),
                        EventRecord.source_type.ilike(f"%{search}%"),
                    )
                )
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
        search: str | None,
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
            if search:
                query = query.where(
                    or_(
                        AlertRecord.title.ilike(f"%{search}%"),
                        AlertRecord.description.ilike(f"%{search}%"),
                        AlertRecord.detector.ilike(f"%{search}%"),
                    )
                )
            if since_minutes:
                query = query.where(
                    AlertRecord.created_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
                )
            rows = (await session.execute(query)).scalars().all()
            return [self._alert_dict(row) for row in rows]

    async def list_dead_letters(
        self,
        *,
        stream_client: Redis,
        state_client: Redis,
        limit: int,
        stream_name: str | None,
    ) -> list[dict[str, Any]]:
        reliability = StreamReliabilityManager(
            stream_client,
            state_client,
            stream_name=settings.ingest_stream,
            group_name=settings.ingest_group,
            consumer_name=settings.worker_id,
        )
        items = await reliability.dead_letter_items(limit)
        if stream_name:
            items = [item for item in items if item.get("stream") == stream_name]
        return items

    async def list_ingest_audit(
        self,
        *,
        limit: int,
        outcome: str | None,
        agent_id: str | None,
        since_minutes: int | None,
    ) -> list[dict[str, Any]]:
        async with session_maker() as session:
            query = select(IngestAuditRecord).order_by(IngestAuditRecord.created_at.desc()).limit(limit)
            if outcome:
                query = query.where(IngestAuditRecord.outcome == outcome)
            if agent_id:
                query = query.where(IngestAuditRecord.agent_id == agent_id)
            if since_minutes:
                query = query.where(
                    IngestAuditRecord.created_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
                )
            rows = (await session.execute(query)).scalars().all()
            return [
                {
                    "id": row.id,
                    "created_at": row.created_at.isoformat(),
                    "agent_id": row.agent_id,
                    "source_ip": row.source_ip,
                    "outcome": row.outcome,
                    "reason": row.reason,
                    "details": row.details,
                }
                for row in rows
            ]

    async def record_ingest_audit(
        self,
        *,
        agent_id: str | None,
        source_ip: str | None,
        outcome: str,
        reason: str,
        details: dict[str, Any],
    ) -> None:
        async with session_maker() as session:
            session.add(
                IngestAuditRecord(
                    created_at=datetime.now(timezone.utc),
                    agent_id=agent_id,
                    source_ip=source_ip,
                    outcome=outcome,
                    reason=reason,
                    details=details,
                )
            )
            await session.commit()

    def _event_dict(self, row: EventRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "timestamp": row.timestamp.isoformat(),
            "received_at": row.received_at.isoformat(),
            "agent_id": row.agent_id,
            "ingest_source_ip": row.ingest_source_ip,
            "source_type": row.source_type,
            "event_type": row.event_type,
            "parser_status": row.parser_status,
            "parser_error": row.parser_error,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "destination_port": row.destination_port,
            "severity": row.severity,
            "raw_message": row.raw_message,
            "payload": row.payload,
            "enrichment": row.enrichment,
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
            "metadata": row.alert_metadata,
            "evidence": row.evidence,
            "integrity_hash": row.integrity_hash,
        }


class WorkerPipeline:
    def __init__(
        self,
        *,
        stream_client: Redis,
        pubsub_client: Redis,
        state_store: AbstractStateStore,
    ) -> None:
        self.stream = stream_client
        self.pubsub = pubsub_client
        self.state = state_store
        self.normalizer = Normalizer()
        self.enrichment = EnrichmentService()
        self.detector = DetectionEngine(state_store, settings.yaml_rules_path)
        self.correlator = CorrelationEngine(state_store, settings.correlation_rules_path)
        self.integrity = IntegrityService()

    async def process(
        self,
        *,
        message_id: str,
        source_type: str,
        line: str,
        received_at: str,
        agent_id: str | None,
        ingest_source_ip: str | None,
    ) -> None:
        parse_result = self.normalizer.normalize(source_type, line)
        event = parse_result.event
        event.metadata["agent_id"] = agent_id or "unknown"
        event.metadata["ingest_source_ip"] = ingest_source_ip
        event.metadata["ingest_message_id"] = message_id
        event.metadata["raw_line"] = line

        enrichment = self.enrichment.enrich(
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=str(event.metadata.get("username") or "") or None,
            source_type=event.source_type,
        )
        event.metadata["enrichment"] = enrichment

        event_id = await self._store_event(
            event,
            received_at=received_at,
            agent_id=agent_id,
            ingest_source_ip=ingest_source_ip,
            ingest_message_id=message_id,
        )
        detector_alerts = await self.detector.run(event)
        for alert in detector_alerts:
            await self._store_alert(alert, related_event_ids=[event_id], source_agent=agent_id)
            correlated = await self.correlator.run(alert)
            for corr in correlated:
                await self._store_alert(
                    corr,
                    related_event_ids=[event_id],
                    related_alert_ids=[alert.alert_id],
                    source_agent=agent_id,
                )

    async def _store_event(
        self,
        event: NormalizedEvent,
        *,
        received_at: str,
        agent_id: str | None,
        ingest_source_ip: str | None,
        ingest_message_id: str,
    ) -> int:
        async with session_maker() as session:
            existing = await session.scalar(
                select(EventRecord).where(EventRecord.payload["ingest_message_id"].astext == ingest_message_id)
            )
            if existing is not None:
                return int(existing.id)

            payload = event.to_payload()
            integrity_hash = hash_payload(payload)
            dt_received = datetime.fromisoformat(received_at)
            row = EventRecord(
                timestamp=event.timestamp,
                received_at=dt_received,
                agent_id=agent_id,
                ingest_source_ip=ingest_source_ip,
                source_type=event.source_type,
                event_type=event.event_type,
                parser_status=event.parser_status,
                parser_error=event.parser_error,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                severity=event.severity,
                raw_message=event.raw_message,
                payload=payload,
                enrichment=payload.get("enrichment", {}),
                integrity_hash=integrity_hash,
            )
            session.add(row)
            await session.flush()
            event_id = int(row.id)
            await session.commit()

        await self.integrity.append(entity_type="event", entity_id=str(event_id), payload=payload, related_hashes=[])
        await self._publish_live(
            {
                "kind": "event",
                "payload": {
                    "id": event_id,
                    "agent_id": agent_id,
                    "ingest_source_ip": ingest_source_ip,
                    **payload,
                },
            }
        )
        return event_id

    async def _store_alert(
        self,
        alert: Alert,
        *,
        related_event_ids: list[int],
        related_alert_ids: list[str] | None = None,
        source_agent: str | None = None,
    ) -> None:
        payload = alert.to_dict()
        payload["metadata"] = {
            **payload.get("metadata", {}),
            "related_event_ids": related_event_ids,
            "related_alert_ids": related_alert_ids or [],
            "source_agent": source_agent,
        }
        integrity_hash = hash_payload(payload)

        async with session_maker() as session:
            existing = await session.scalar(select(AlertRecord).where(AlertRecord.id == alert.alert_id))
            if existing is None:
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
                        alert_metadata=payload["metadata"],
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
        await self._publish_live({"kind": "alert", "payload": payload})
        await self.stream.xadd(
            settings.alert_stream,
            {"alert": json.dumps(payload, default=str), "source_agent": source_agent or "unknown"},
            maxlen=settings.stream_maxlen,
            approximate=True,
        )

    async def _publish_live(self, payload: dict[str, Any]) -> None:
        try:
            await self.pubsub.publish(settings.live_channel, json.dumps(payload, default=str))
        except Exception:
            LOGGER.exception("failed to publish live notification kind=%s", payload.get("kind"))


class AlertDispatcher:
    def __init__(self, *, state_store: AbstractStateStore) -> None:
        self.state = state_store

    async def deliver(self, payload: dict[str, Any]) -> None:
        severity = str(payload.get("severity", "medium")).lower()
        alert_id = str(payload.get("id") or "")
        if alert_id:
            delivered = await self.state.get_json(f"siem:dispatch:{alert_id}")
            if delivered is not None:
                return
        if severity in {"critical", "high"}:
            await self._send_webhook(payload, severity)
            await self._send_email(payload, severity)
        if alert_id:
            await self.state.set_json(
                f"siem:dispatch:{alert_id}",
                {"delivered_at": datetime.now(timezone.utc).isoformat()},
                settings.alert_retention_days * 86400,
            )

    async def _send_webhook(self, payload: dict[str, Any], severity: str) -> None:
        url = settings.webhook_url_critical if severity == "critical" else settings.webhook_url_high
        if not url:
            return
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(url, json={"text": self._render_message(payload), "payload": payload})
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
        metadata = payload.get("metadata") or {}
        return (
            f"Alert: {payload.get('title')}\n"
            f"Severity: {payload.get('severity')}\n"
            f"Detector: {payload.get('detector')}\n"
            f"Rule: {payload.get('rule_id')}\n"
            f"Source IP: {payload.get('source_ip')}\n"
            f"Source Agent: {metadata.get('source_agent')}\n"
            f"Description: {payload.get('description')}\n"
        )
