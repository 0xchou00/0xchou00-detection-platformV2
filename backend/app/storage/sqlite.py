from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator

from app.models.alert import Alert
from app.models.event import LogEvent


DEFAULT_DB_PATH = Path(
    os.getenv(
        "SIEM_DB_PATH",
        str(Path(__file__).resolve().parents[3] / "backend" / "data" / "0xchou00-tool.db"),
    )
)


@dataclass(slots=True)
class APIKeyRecord:
    key_id: str
    name: str
    role: str
    is_active: bool


class SQLiteStorage:
    """Persist logs, alerts, enrichment cache, and the integrity contract chain in SQLite."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    hostname TEXT,
                    username TEXT,
                    process TEXT,
                    protocol TEXT,
                    status TEXT,
                    severity TEXT NOT NULL,
                    http_method TEXT,
                    http_path TEXT,
                    http_status INTEGER,
                    http_user_agent TEXT,
                    country TEXT,
                    risk_score INTEGER,
                    enrichment_source TEXT,
                    threat_labels_json TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    normalized_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    detector TEXT NOT NULL,
                    alert_kind TEXT NOT NULL DEFAULT 'detection',
                    correlation_rule_id TEXT,
                    correlation_fingerprint TEXT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_ip TEXT,
                    event_count INTEGER NOT NULL,
                    evidence_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    api_key TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chain_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    related_hashes_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    contract_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    risk_score INTEGER,
                    source TEXT,
                    threat_labels_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_source_type ON logs(source_type, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_destination_port ON logs(destination_port, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(alert_kind, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_correlation_fingerprint
                    ON alerts(correlation_fingerprint)
                    WHERE correlation_fingerprint IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_chain_sequence ON chain_entries(sequence);
                CREATE INDEX IF NOT EXISTS idx_chain_entity ON chain_entries(entity_type, entity_id, sequence DESC);
                """
            )
            self._migrate_logs_table(conn)
            self._migrate_alerts_table(conn)
            self._migrate_chain_entries_table(conn)
            self._migrate_enrichment_cache(conn)

        self.seed_default_api_keys()

    def seed_default_api_keys(self) -> None:
        defaults = {
            "admin": os.getenv("SIEM_ADMIN_API_KEY", "siem-admin-dev-key"),
            "analyst": os.getenv("SIEM_ANALYST_API_KEY", "siem-analyst-dev-key"),
            "viewer": os.getenv("SIEM_VIEWER_API_KEY", "siem-viewer-dev-key"),
        }

        with self.connection() as conn:
            for role, api_key in defaults.items():
                existing = conn.execute(
                    "SELECT id FROM api_keys WHERE api_key = ?",
                    (api_key,),
                ).fetchone()
                if existing:
                    continue

                conn.execute(
                    """
                    INSERT INTO api_keys (id, name, api_key, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                    """,
                    (
                        secrets.token_urlsafe(12),
                        f"Default {role.title()} Key",
                        api_key,
                        role,
                        self._utc_now(),
                    ),
                )

    def validate_api_key(self, api_key: str) -> APIKeyRecord | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, role, is_active
                FROM api_keys
                WHERE api_key = ? AND is_active = 1
                """,
                (api_key,),
            ).fetchone()

        if not row:
            return None

        return APIKeyRecord(
            key_id=row["id"],
            name=row["name"],
            role=row["role"],
            is_active=bool(row["is_active"]),
        )

    def insert_event(self, event: LogEvent) -> int:
        payload = event.to_dict()
        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO logs (
                    timestamp, source_type, event_type, source_ip, destination_ip,
                    destination_port, hostname, username, process, protocol, status,
                    severity, http_method, http_path, http_status, http_user_agent,
                    country, risk_score, enrichment_source, threat_labels_json,
                    raw_message, normalized_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["timestamp"],
                    event.source_type,
                    event.event_type,
                    event.source_ip,
                    event.destination_ip,
                    event.destination_port,
                    event.hostname,
                    event.username,
                    event.process,
                    event.protocol,
                    event.status,
                    event.severity,
                    event.http_method,
                    event.http_path,
                    event.http_status,
                    event.http_user_agent,
                    event.country,
                    event.risk_score,
                    event.enrichment_source,
                    json.dumps(event.threat_labels, sort_keys=True),
                    event.raw_message,
                    json.dumps(payload, sort_keys=True, default=str),
                    self._utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    def insert_alert(self, alert: Alert) -> str:
        payload = alert.to_dict()
        metadata = payload["metadata"]
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id, detector, alert_kind, correlation_rule_id, correlation_fingerprint,
                    severity, title, description, source_type, source_ip, event_count,
                    evidence_json, metadata_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.detector,
                    metadata.get("alert_kind", "detection"),
                    metadata.get("correlation_rule_id"),
                    metadata.get("correlation_fingerprint"),
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.source_type,
                    alert.source_ip,
                    alert.event_count,
                    json.dumps(payload["evidence"], sort_keys=True, default=str),
                    json.dumps(metadata, sort_keys=True, default=str),
                    payload["created_at"],
                ),
            )
        return alert.alert_id

    def list_logs(
        self,
        *,
        limit: int = 100,
        source_type: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, timestamp, source_type, event_type, source_ip, destination_ip, destination_port,
                   hostname, username, process, protocol, status, severity, http_method, http_path,
                   http_status, http_user_agent, country, risk_score, enrichment_source,
                   threat_labels_json, raw_message, normalized_json, created_at
            FROM logs
        """
        conditions: list[str] = []
        params: list[Any] = []

        if source_type:
            conditions.append("source_type = ?")
            params.append(source_type)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["threat_labels"] = json.loads(item.pop("threat_labels_json"))
            item["normalized"] = json.loads(item.pop("normalized_json"))
            results.append(item)
        return results

    def list_alerts(
        self,
        *,
        limit: int = 100,
        severity: str | None = None,
        detector: str | None = None,
        source_type: str | None = None,
        since: str | None = None,
        source_ip: str | None = None,
        alert_kind: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, detector, alert_kind, correlation_rule_id, correlation_fingerprint,
                   severity, title, description, source_type, source_ip, event_count,
                   evidence_json, metadata_json, created_at
            FROM alerts
        """
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if source_type:
            conditions.append("source_type = ?")
            params.append(source_type)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if alert_kind:
            conditions.append("alert_kind = ?")
            params.append(alert_kind)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_alert_dict(row) for row in rows]

    def get_counts(self) -> dict[str, int]:
        with self.connection() as conn:
            logs_count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            alerts_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"logs": int(logs_count), "alerts": int(alerts_count)}

    def correlation_fingerprint_exists(self, fingerprint: str) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT id FROM alerts WHERE correlation_fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        return row is not None

    def get_enrichment_cache(self, ip: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT ip, country, risk_score, source, threat_labels_json,
                       payload_json, updated_at, expires_at
                FROM enrichment_cache
                WHERE ip = ?
                """,
                (ip,),
            ).fetchone()
        if not row:
            return None
        if row["expires_at"] < self._utc_now():
            return None
        payload = json.loads(row["payload_json"])
        return {
            "ip": row["ip"],
            "country": row["country"],
            "risk_score": row["risk_score"],
            "source": row["source"],
            "threat_labels": json.loads(row["threat_labels_json"]),
            "payload": payload,
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
        }

    def upsert_enrichment_cache(self, ip: str, payload: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO enrichment_cache (
                    ip, country, risk_score, source, threat_labels_json, payload_json, updated_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    country = excluded.country,
                    risk_score = excluded.risk_score,
                    source = excluded.source,
                    threat_labels_json = excluded.threat_labels_json,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at
                """,
                (
                    ip,
                    payload.get("country"),
                    payload.get("risk_score"),
                    payload.get("source"),
                    json.dumps(payload.get("threat_labels") or [], sort_keys=True),
                    json.dumps(payload.get("payload") or {}, sort_keys=True),
                    self._utc_now(),
                    payload["expires_at"],
                ),
            )

    def append_chain_entry(
        self,
        *,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
        related_entities: list[dict[str, str]],
    ) -> dict[str, Any]:
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        payload_hash = sha256(payload_json.encode("utf-8")).hexdigest()
        created_at = self._utc_now()
        related_hashes = self._resolve_related_hashes(related_entities)
        related_hashes_json = json.dumps(related_hashes, sort_keys=True)

        with self.connection() as conn:
            previous = conn.execute(
                """
                SELECT sequence, contract_hash
                FROM chain_entries
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()
            prev_hash = previous["contract_hash"] if previous else "0" * 64
            contract_hash = self._compute_contract_hash(
                entity_type=entity_type,
                entity_id=entity_id,
                payload_hash=payload_hash,
                related_hashes_json=related_hashes_json,
                prev_hash=prev_hash,
                created_at=created_at,
            )
            cursor = conn.execute(
                """
                INSERT INTO chain_entries (
                    entity_type, entity_id, payload_hash, related_hashes_json, prev_hash,
                    contract_hash, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity_type,
                    entity_id,
                    payload_hash,
                    related_hashes_json,
                    prev_hash,
                    contract_hash,
                    created_at,
                ),
            )
            sequence = int(cursor.lastrowid)

        return {
            "sequence": sequence,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "payload_hash": payload_hash,
            "related_hashes": related_hashes,
            "prev_hash": prev_hash,
            "contract_hash": contract_hash,
            "created_at": created_at,
        }

    def verify_chain(self) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT sequence, entity_type, entity_id, payload_hash, related_hashes_json,
                       prev_hash, contract_hash, created_at
                FROM chain_entries
                ORDER BY sequence ASC
                """
            ).fetchall()

        if not rows:
            return {
                "valid": True,
                "entries": 0,
                "chain_head": None,
                "errors": [],
            }

        expected_prev_hash = "0" * 64
        errors: list[str] = []

        for row in rows:
            item = dict(row)
            expected_hash = self._compute_contract_hash(
                entity_type=item["entity_type"],
                entity_id=item["entity_id"],
                payload_hash=item["payload_hash"],
                related_hashes_json=item["related_hashes_json"],
                prev_hash=item["prev_hash"],
                created_at=item["created_at"],
            )

            if item["prev_hash"] != expected_prev_hash:
                errors.append(f"Sequence {item['sequence']} has broken prev_hash linkage.")

            if item["contract_hash"] != expected_hash:
                errors.append(f"Sequence {item['sequence']} has an invalid contract hash.")

            current_payload_hash = self._load_entity_payload_hash(
                entity_type=item["entity_type"],
                entity_id=item["entity_id"],
            )
            if current_payload_hash is None:
                errors.append(
                    f"Sequence {item['sequence']} references a missing {item['entity_type']} entity."
                )
            elif current_payload_hash != item["payload_hash"]:
                errors.append(
                    f"Sequence {item['sequence']} payload hash does not match the stored {item['entity_type']} entity."
                )

            if not self._related_hashes_valid(json.loads(item["related_hashes_json"])):
                errors.append(
                    f"Sequence {item['sequence']} contains broken related entity hashes."
                )

            expected_prev_hash = item["contract_hash"]

        return {
            "valid": len(errors) == 0,
            "entries": len(rows),
            "chain_head": rows[-1]["contract_hash"],
            "errors": errors,
        }

    def _resolve_related_hashes(self, related_entities: list[dict[str, str]]) -> list[dict[str, str]]:
        resolved: list[dict[str, str]] = []
        for item in related_entities:
            entity_type = item["entity_type"]
            entity_id = item["entity_id"]
            related_hash = self._latest_contract_hash(entity_type=entity_type, entity_id=entity_id)
            if not related_hash:
                continue
            resolved.append(
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "contract_hash": related_hash,
                }
            )
        return resolved

    def _related_hashes_valid(self, related_hashes: list[dict[str, str]]) -> bool:
        for item in related_hashes:
            current = self._latest_contract_hash(
                entity_type=item["entity_type"],
                entity_id=item["entity_id"],
            )
            if current != item["contract_hash"]:
                return False
        return True

    def _latest_contract_hash(self, *, entity_type: str, entity_id: str) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT contract_hash
                FROM chain_entries
                WHERE entity_type = ? AND entity_id = ?
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (entity_type, entity_id),
            ).fetchone()
        return row["contract_hash"] if row else None

    def _compute_contract_hash(
        self,
        *,
        entity_type: str,
        entity_id: str,
        payload_hash: str,
        related_hashes_json: str,
        prev_hash: str,
        created_at: str,
    ) -> str:
        material = json.dumps(
            {
                "version": "0xchou00-contract-v2",
                "entity_type": entity_type,
                "entity_id": entity_id,
                "payload_hash": payload_hash,
                "related_hashes": json.loads(related_hashes_json),
                "prev_hash": prev_hash,
                "created_at": created_at,
            },
            sort_keys=True,
        )
        return sha256(material.encode("utf-8")).hexdigest()

    def _load_entity_payload_hash(self, *, entity_type: str, entity_id: str) -> str | None:
        with self.connection() as conn:
            if entity_type == "log":
                row = conn.execute(
                    "SELECT normalized_json FROM logs WHERE id = ?",
                    (entity_id,),
                ).fetchone()
                if not row:
                    return None
                payload = row["normalized_json"]
            elif entity_type == "alert":
                row = conn.execute(
                    """
                    SELECT id, detector, alert_kind, correlation_rule_id, correlation_fingerprint,
                           severity, title, description, source_type, source_ip, event_count,
                           evidence_json, metadata_json, created_at
                    FROM alerts
                    WHERE id = ?
                    """,
                    (entity_id,),
                ).fetchone()
                if not row:
                    return None
                payload = json.dumps(
                    {
                        "alert_id": row["id"],
                        "detector": row["detector"],
                        "severity": row["severity"],
                        "title": row["title"],
                        "description": row["description"],
                        "source_type": row["source_type"],
                        "source_ip": row["source_ip"],
                        "event_count": row["event_count"],
                        "evidence": json.loads(row["evidence_json"]),
                        "metadata": json.loads(row["metadata_json"]),
                        "created_at": row["created_at"],
                    },
                    sort_keys=True,
                )
            else:
                return None

        return sha256(payload.encode("utf-8")).hexdigest()

    def _migrate_logs_table(self, conn: sqlite3.Connection) -> None:
        self._ensure_column(conn, "logs", "destination_ip", "TEXT")
        self._ensure_column(conn, "logs", "destination_port", "INTEGER")
        self._ensure_column(conn, "logs", "process", "TEXT")
        self._ensure_column(conn, "logs", "protocol", "TEXT")
        self._ensure_column(conn, "logs", "status", "TEXT")
        self._ensure_column(conn, "logs", "http_method", "TEXT")
        self._ensure_column(conn, "logs", "http_path", "TEXT")
        self._ensure_column(conn, "logs", "http_status", "INTEGER")
        self._ensure_column(conn, "logs", "http_user_agent", "TEXT")
        self._ensure_column(conn, "logs", "country", "TEXT")
        self._ensure_column(conn, "logs", "risk_score", "INTEGER")
        self._ensure_column(conn, "logs", "enrichment_source", "TEXT")
        self._ensure_column(conn, "logs", "threat_labels_json", "TEXT NOT NULL DEFAULT '[]'")

    def _migrate_alerts_table(self, conn: sqlite3.Connection) -> None:
        self._ensure_column(conn, "alerts", "alert_kind", "TEXT NOT NULL DEFAULT 'detection'")
        self._ensure_column(conn, "alerts", "correlation_rule_id", "TEXT")
        self._ensure_column(conn, "alerts", "correlation_fingerprint", "TEXT")

    def _migrate_chain_entries_table(self, conn: sqlite3.Connection) -> None:
        self._ensure_column(conn, "chain_entries", "related_hashes_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column(conn, "chain_entries", "contract_hash", "TEXT")
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(chain_entries)").fetchall()
        }
        if "entry_hash" in columns and "contract_hash" in columns:
            conn.execute(
                """
                UPDATE chain_entries
                SET contract_hash = entry_hash
                WHERE contract_hash IS NULL OR contract_hash = ''
                """
            )

    def _migrate_enrichment_cache(self, conn: sqlite3.Connection) -> None:
        self._ensure_column(conn, "enrichment_cache", "risk_score", "INTEGER")
        self._ensure_column(conn, "enrichment_cache", "threat_labels_json", "TEXT NOT NULL DEFAULT '[]'")

    def _ensure_column(self, conn: sqlite3.Connection, table_name: str, column_name: str, column_sql: str) -> None:
        existing = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name in existing:
            return
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")

    def _row_to_alert_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["metadata"] = json.loads(item.pop("metadata_json"))
        return item

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
