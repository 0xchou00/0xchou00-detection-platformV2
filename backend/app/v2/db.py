from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.v2.config import settings


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    raw_message: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB)
    integrity_hash: Mapped[str] = mapped_column(String(128), index=True)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    detector: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), index=True)
    alert_kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    event_count: Mapped[int] = mapped_column(Integer)
    metadata: Mapped[dict] = mapped_column(JSONB)
    evidence: Mapped[list] = mapped_column(JSONB)
    integrity_hash: Mapped[str] = mapped_column(String(128), index=True)


class IntegrityChainRecord(Base):
    __tablename__ = "integrity_chain"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
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


engine = create_async_engine(settings.postgres_dsn, pool_pre_ping=True, future=True)
session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def initialize_database() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_maker() as session:
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
        await session.commit()

