from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Identity, Integer, String, Text, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.v2.config import settings


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"
    __table_args__ = {"postgresql_partition_by": "RANGE (received_at)"}

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(128), index=True)
    ingest_source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    parser_status: Mapped[str] = mapped_column(String(16), index=True, default="parsed")
    parser_error: Mapped[dict | None] = mapped_column(JSONB, default=None)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    raw_message: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB)
    enrichment: Mapped[dict] = mapped_column(JSONB, default=dict)
    integrity_hash: Mapped[str] = mapped_column(String(128), index=True)


class AlertRecord(Base):
    __tablename__ = "alerts"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    detector: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), index=True)
    alert_kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    event_count: Mapped[int] = mapped_column(Integer)
    alert_metadata: Mapped[dict] = mapped_column("metadata", JSONB)
    evidence: Mapped[list] = mapped_column(JSONB)
    integrity_hash: Mapped[str] = mapped_column(String(128), index=True)


class IntegrityChainRecord(Base):
    __tablename__ = "integrity_chain"

    sequence: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_id: Mapped[str] = mapped_column(String(128), index=True)
    prev_hash: Mapped[str] = mapped_column(String(128))
    payload_hash: Mapped[str] = mapped_column(String(128))
    related_hashes: Mapped[list] = mapped_column(JSONB)
    contract_hash: Mapped[str] = mapped_column(String(128), index=True)


class APIKeyRecord(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    api_key: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AgentCredentialRecord(Base):
    __tablename__ = "agent_credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(128))
    api_key: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    signing_secret: Mapped[str] = mapped_column(String(256))
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    rate_limit_per_window: Mapped[int] = mapped_column(Integer, default=settings.default_agent_rate_limit)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    rotated_from: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class IngestAuditRecord(Base):
    __tablename__ = "ingest_audit"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(128), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(String(128), index=True)
    details: Mapped[dict] = mapped_column(JSONB)


engine = create_async_engine(settings.postgres_dsn, pool_pre_ping=True, future=True)
session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def initialize_database() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_range_partitions(conn, "events", "received_at")
        await _ensure_range_partitions(conn, "alerts", "created_at")
        await _ensure_range_partitions(conn, "ingest_audit", "created_at")
        await _ensure_parent_indexes(conn)

    async with session_maker() as session:
        await _seed_user_api_keys(session)
        await _seed_default_agent(session)
        await session.commit()


async def _seed_user_api_keys(session: AsyncSession) -> None:
    for role, api_key in (
        ("admin", settings.admin_api_key),
        ("analyst", settings.analyst_api_key),
        ("viewer", settings.viewer_api_key),
    ):
        existing = await session.scalar(select(APIKeyRecord).where(APIKeyRecord.api_key == api_key))
        if existing:
            continue

        session.add(
            APIKeyRecord(
                id=secrets.token_urlsafe(12),
                name=f"Default {role.title()} Key",
                api_key=api_key,
                role=role,
                is_active=True,
                created_at=utcnow(),
            )
        )


async def _seed_default_agent(session: AsyncSession) -> None:
    existing = await session.scalar(
        select(AgentCredentialRecord).where(
            AgentCredentialRecord.agent_id == settings.default_agent_id,
            AgentCredentialRecord.is_active.is_(True),
        )
    )
    if existing:
        return

    session.add(
        AgentCredentialRecord(
            id=secrets.token_urlsafe(12),
            agent_id=settings.default_agent_id,
            name="Default Lab Agent",
            api_key=settings.default_agent_api_key,
            signing_secret=settings.default_agent_signing_secret,
            key_version=1,
            rate_limit_per_window=settings.default_agent_rate_limit,
            is_active=True,
            created_at=utcnow(),
        )
    )


async def _ensure_range_partitions(conn: AsyncConnection, table_name: str, column_name: str) -> None:
    now = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for month_offset in range(0, settings.partition_months_ahead + 1):
        start = _month_start(now.year, now.month + month_offset)
        end = _month_start(start.year, start.month + 1)
        suffix = f"{start.year}{start.month:02d}"
        await conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS {table_name}_{suffix}
                PARTITION OF {table_name}
                FOR VALUES FROM (:start_value) TO (:end_value)
                """
            ),
            {"start_value": start, "end_value": end},
        )


async def _ensure_parent_indexes(conn: AsyncConnection) -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_events_source_type_time ON events (source_type, received_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip_time ON events (source_ip, received_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_parser_status_time ON events (parser_status, received_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_ingest_message_id ON events ((payload->>'ingest_message_id'))",
        "CREATE INDEX IF NOT EXISTS idx_events_payload_gin ON events USING GIN (payload)",
        "CREATE INDEX IF NOT EXISTS idx_events_enrichment_gin ON events USING GIN (enrichment)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_detector_time ON alerts (detector, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_rule_time ON alerts (rule_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip_time ON alerts (source_ip, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_metadata_gin ON alerts USING GIN (metadata)",
        "CREATE INDEX IF NOT EXISTS idx_ingest_audit_agent_time ON ingest_audit (agent_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_ingest_audit_outcome_time ON ingest_audit (outcome, created_at DESC)",
    ]
    for statement in statements:
        await conn.execute(text(statement))


def _month_start(year: int, month: int) -> datetime:
    normalized_year = year + ((month - 1) // 12)
    normalized_month = ((month - 1) % 12) + 1
    return datetime(normalized_year, normalized_month, 1, tzinfo=timezone.utc)
