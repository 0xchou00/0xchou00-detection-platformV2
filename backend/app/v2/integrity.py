from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from app.v2.db import AlertRecord, EventRecord, IntegrityChainRecord, session_maker


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class IntegrityService:
    async def append(self, *, entity_type: str, entity_id: str, payload: dict[str, Any], related_hashes: list[str]) -> str:
        payload_hash = _sha(json.dumps(payload, sort_keys=True, default=str))
        async with session_maker() as session:
            prev = await session.scalar(
                select(IntegrityChainRecord.contract_hash).order_by(IntegrityChainRecord.sequence.desc()).limit(1)
            )
            prev_hash = prev or ("0" * 64)
            created_at = datetime.now(timezone.utc)
            material = json.dumps(
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "payload_hash": payload_hash,
                    "related_hashes": related_hashes,
                    "prev_hash": prev_hash,
                    "created_at": created_at.isoformat(),
                },
                sort_keys=True,
            )
            contract_hash = _sha(material)
            session.add(
                IntegrityChainRecord(
                    created_at=created_at,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    prev_hash=prev_hash,
                    payload_hash=payload_hash,
                    related_hashes=related_hashes,
                    contract_hash=contract_hash,
                )
            )
            await session.commit()
            return contract_hash

    async def verify(self, limit: int = 100000) -> dict[str, Any]:
        async with session_maker() as session:
            rows = (
                (
                    await session.execute(
                        select(IntegrityChainRecord).order_by(IntegrityChainRecord.sequence.asc()).limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            total = await session.scalar(select(func.count()).select_from(IntegrityChainRecord))
            errors: list[str] = []
            expected_prev = "0" * 64
            for row in rows:
                material = json.dumps(
                    {
                        "entity_type": row.entity_type,
                        "entity_id": row.entity_id,
                        "payload_hash": row.payload_hash,
                        "related_hashes": row.related_hashes,
                        "prev_hash": row.prev_hash,
                        "created_at": row.created_at.isoformat(),
                    },
                    sort_keys=True,
                )
                recomputed = _sha(material)
                if row.prev_hash != expected_prev:
                    errors.append(f"Broken prev_hash at sequence {row.sequence}")
                if row.contract_hash != recomputed:
                    errors.append(f"Invalid contract hash at sequence {row.sequence}")

                current_hash = await self._entity_hash(session, row.entity_type, row.entity_id)
                if not current_hash:
                    errors.append(f"Missing {row.entity_type}:{row.entity_id}")
                elif current_hash != row.payload_hash:
                    errors.append(f"Payload mismatch for {row.entity_type}:{row.entity_id}")
                expected_prev = row.contract_hash

            return {
                "valid": len(errors) == 0,
                "checked_entries": len(rows),
                "total_entries": int(total or 0),
                "errors": errors[:25],
            }

    async def _entity_hash(self, session, entity_type: str, entity_id: str) -> str | None:
        if entity_type == "event":
            row = await session.scalar(select(EventRecord.payload).where(EventRecord.id == int(entity_id)))
            if row is None:
                return None
            return _sha(json.dumps(row, sort_keys=True, default=str))
        if entity_type == "alert":
            row = await session.execute(select(AlertRecord).where(AlertRecord.id == entity_id))
            alert = row.scalars().first()
            if alert is None:
                return None
            payload = {
                "id": alert.id,
                "detector": alert.detector,
                "rule_id": alert.rule_id,
                "alert_kind": alert.alert_kind,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "source_type": alert.source_type,
                "source_ip": alert.source_ip,
                "event_count": alert.event_count,
                "evidence": alert.evidence,
                "metadata": alert.alert_metadata,
                "created_at": alert.created_at.astimezone(timezone.utc).isoformat(),
            }
            return _sha(json.dumps(payload, sort_keys=True, default=str))
        return None
