from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[3]
RULES_DIR = BASE_DIR / "backend" / "rules"
CONFIG_DIR = BASE_DIR / "backend" / "config"


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(slots=True)
class Settings:
    service_name: str = "0xchou00 Detection Platform V2"
    api_host: str = field(default_factory=lambda: os.getenv("SIEM_API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(os.getenv("SIEM_API_PORT", "8000")))
    allowed_origins: list[str] = field(
        default_factory=lambda: _split_csv(
            os.getenv(
                "SIEM_ALLOWED_ORIGINS",
                "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
            )
        )
    )
    postgres_dsn: str = field(
        default_factory=lambda: os.getenv(
            "SIEM_POSTGRES_DSN",
            "postgresql+asyncpg://siem:siem@127.0.0.1:5432/siem",
        )
    )
    stream_redis_url: str = field(
        default_factory=lambda: os.getenv(
            "SIEM_STREAM_REDIS_URL",
            os.getenv("SIEM_REDIS_URL", "redis://127.0.0.1:6379/0"),
        )
    )
    pubsub_redis_url: str = field(
        default_factory=lambda: os.getenv(
            "SIEM_PUBSUB_REDIS_URL",
            os.getenv("SIEM_REDIS_URL", "redis://127.0.0.1:6379/1"),
        )
    )
    state_redis_url: str = field(
        default_factory=lambda: os.getenv(
            "SIEM_STATE_REDIS_URL",
            os.getenv("SIEM_REDIS_URL", "redis://127.0.0.1:6379/2"),
        )
    )
    ingest_stream: str = field(default_factory=lambda: os.getenv("SIEM_INGEST_STREAM", "siem:ingest"))
    alert_stream: str = field(default_factory=lambda: os.getenv("SIEM_ALERT_STREAM", "siem:alerts"))
    dead_letter_stream: str = field(default_factory=lambda: os.getenv("SIEM_DEAD_LETTER_STREAM", "siem:dead-letter"))
    live_channel: str = field(default_factory=lambda: os.getenv("SIEM_LIVE_CHANNEL", "siem:live"))
    ingest_group: str = field(default_factory=lambda: os.getenv("SIEM_INGEST_GROUP", "workers"))
    alert_group: str = field(default_factory=lambda: os.getenv("SIEM_ALERT_GROUP", "alerting"))
    stream_maxlen: int = field(default_factory=lambda: int(os.getenv("SIEM_STREAM_MAXLEN", "250000")))
    worker_batch_size: int = field(default_factory=lambda: int(os.getenv("SIEM_WORKER_BATCH_SIZE", "250")))
    worker_block_ms: int = field(default_factory=lambda: int(os.getenv("SIEM_WORKER_BLOCK_MS", "3000")))
    worker_id: str = field(default_factory=lambda: os.getenv("SIEM_WORKER_ID", "worker-1"))
    alerter_id: str = field(default_factory=lambda: os.getenv("SIEM_ALERTER_ID", "alerter-1"))
    stream_claim_idle_ms: int = field(default_factory=lambda: int(os.getenv("SIEM_STREAM_CLAIM_IDLE_MS", "15000")))
    stream_retry_limit: int = field(default_factory=lambda: int(os.getenv("SIEM_STREAM_RETRY_LIMIT", "5")))
    stream_retry_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_STREAM_RETRY_TTL_SECONDS", "604800"))
    )
    pubsub_message_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_PUBSUB_MESSAGE_TTL_SECONDS", "60"))
    )
    state_default_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_STATE_DEFAULT_TTL_SECONDS", "21600"))
    )
    correlation_history_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_CORRELATION_HISTORY_TTL_SECONDS", "10800"))
    )
    replay_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_REPLAY_WINDOW_SECONDS", "300"))
    )
    rate_limit_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_RATE_LIMIT_WINDOW_SECONDS", "60"))
    )
    default_agent_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("SIEM_DEFAULT_AGENT_RATE_LIMIT", "600"))
    )
    require_tls_for_ingest: bool = field(
        default_factory=lambda: os.getenv("SIEM_REQUIRE_TLS_FOR_INGEST", "false").lower() == "true"
    )
    allowed_clock_skew_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_ALLOWED_CLOCK_SKEW_SECONDS", "300"))
    )
    yaml_rules_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_RULES_PATH", str(RULES_DIR / "default_rules.yml")))
    )
    correlation_rules_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("SIEM_CORRELATION_RULES_PATH", str(RULES_DIR / "correlation_rules.yml"))
        )
    )
    assets_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_ASSETS_PATH", str(CONFIG_DIR / "assets.yml")))
    )
    identities_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_IDENTITIES_PATH", str(CONFIG_DIR / "identities.yml")))
    )
    reputation_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_REPUTATION_PATH", str(CONFIG_DIR / "reputation.yml")))
    )
    suppressions_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_SUPPRESSIONS_PATH", str(CONFIG_DIR / "suppressions.yml")))
    )
    geoip_city_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_GEOIP_CITY_PATH", str(BASE_DIR / "backend" / "data" / "GeoLite2-City.mmdb")))
    )
    geoip_asn_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIEM_GEOIP_ASN_PATH", str(BASE_DIR / "backend" / "data" / "GeoLite2-ASN.mmdb")))
    )
    smtp_host: str | None = field(default_factory=lambda: os.getenv("SIEM_SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SIEM_SMTP_PORT", "587")))
    smtp_user: str | None = field(default_factory=lambda: os.getenv("SIEM_SMTP_USER"))
    smtp_password: str | None = field(default_factory=lambda: os.getenv("SIEM_SMTP_PASSWORD"))
    smtp_sender: str = field(default_factory=lambda: os.getenv("SIEM_SMTP_SENDER", "siem@localhost"))
    smtp_tls: bool = field(default_factory=lambda: os.getenv("SIEM_SMTP_TLS", "true").lower() == "true")
    smtp_recipients_high: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("SIEM_SMTP_RECIPIENTS_HIGH", "soc-high@localhost"))
    )
    smtp_recipients_critical: list[str] = field(
        default_factory=lambda: _split_csv(
            os.getenv("SIEM_SMTP_RECIPIENTS_CRITICAL", "soc-critical@localhost")
        )
    )
    webhook_url_high: str | None = field(default_factory=lambda: os.getenv("SIEM_WEBHOOK_HIGH"))
    webhook_url_critical: str | None = field(default_factory=lambda: os.getenv("SIEM_WEBHOOK_CRITICAL"))
    admin_api_key: str = field(default_factory=lambda: os.getenv("SIEM_ADMIN_API_KEY", "siem-admin-dev-key"))
    analyst_api_key: str = field(default_factory=lambda: os.getenv("SIEM_ANALYST_API_KEY", "siem-analyst-dev-key"))
    viewer_api_key: str = field(default_factory=lambda: os.getenv("SIEM_VIEWER_API_KEY", "siem-viewer-dev-key"))
    default_agent_id: str = field(default_factory=lambda: os.getenv("SIEM_AGENT_ID", "lab-agent"))
    default_agent_api_key: str = field(
        default_factory=lambda: os.getenv("SIEM_AGENT_API_KEY", "siem-lab-agent-key")
    )
    default_agent_signing_secret: str = field(
        default_factory=lambda: os.getenv("SIEM_AGENT_SIGNING_SECRET", "siem-lab-agent-secret")
    )
    event_retention_days: int = field(default_factory=lambda: int(os.getenv("SIEM_EVENT_RETENTION_DAYS", "30")))
    alert_retention_days: int = field(default_factory=lambda: int(os.getenv("SIEM_ALERT_RETENTION_DAYS", "90")))
    audit_retention_days: int = field(default_factory=lambda: int(os.getenv("SIEM_AUDIT_RETENTION_DAYS", "30")))
    partition_months_ahead: int = field(default_factory=lambda: int(os.getenv("SIEM_PARTITION_MONTHS_AHEAD", "2")))


settings = Settings()

