from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.v2.config import settings
from app.v2.db import AlertRecord, EventRecord, IngestAuditRecord, initialize_database, session_maker


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("siem-retention")


async def run() -> None:
    await initialize_database()
    now = datetime.now(timezone.utc)
    event_cutoff = now - timedelta(days=settings.event_retention_days)
    alert_cutoff = now - timedelta(days=settings.alert_retention_days)
    audit_cutoff = now - timedelta(days=settings.audit_retention_days)

    async with session_maker() as session:
        deleted_events = await session.execute(delete(EventRecord).where(EventRecord.received_at < event_cutoff))
        deleted_alerts = await session.execute(delete(AlertRecord).where(AlertRecord.created_at < alert_cutoff))
        deleted_audits = await session.execute(delete(IngestAuditRecord).where(IngestAuditRecord.created_at < audit_cutoff))
        await session.commit()

    LOGGER.info(
        "retention completed deleted_events=%s deleted_alerts=%s deleted_audits=%s",
        deleted_events.rowcount or 0,
        deleted_alerts.rowcount or 0,
        deleted_audits.rowcount or 0,
    )


if __name__ == "__main__":
    asyncio.run(run())
