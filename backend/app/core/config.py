from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[3]
RULES_DIR = BASE_DIR / "backend" / "rules"


@dataclass(slots=True)
class BruteForceConfig:
    failure_threshold: int = 5
    window_seconds: int = 60
    critical_multiplier: int = 3


@dataclass(slots=True)
class SuspiciousIPConfig:
    request_rate_threshold: int = 120
    request_rate_window_seconds: int = 60
    error_ratio_threshold: float = 0.5
    error_ratio_min_requests: int = 10
    sensitive_paths: set[str] = field(
        default_factory=lambda: {
            "/.env",
            "/.git/config",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/admin",
            "/backup",
            "/config.php",
            "/xmlrpc.php",
        }
    )


@dataclass(slots=True)
class PortScanConfig:
    distinct_port_threshold: int = field(
        default_factory=lambda: int(os.getenv("SIEM_PORTSCAN_THRESHOLD", "6"))
    )
    window_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_PORTSCAN_WINDOW_SECONDS", "30"))
    )


@dataclass(slots=True)
class EnrichmentConfig:
    geoip_db_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("SIEM_GEOIP_DB_PATH", str(BASE_DIR / "backend" / "data" / "GeoLite2-City.mmdb"))
        )
    )
    static_blacklist_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("SIEM_STATIC_BLACKLIST_PATH", str(RULES_DIR / "static_blacklist.txt"))
        )
    )
    abuseipdb_api_key: str | None = field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY"))
    abuseipdb_url: str = field(
        default_factory=lambda: os.getenv(
            "ABUSEIPDB_URL",
            "https://api.abuseipdb.com/api/v2/check",
        )
    )
    abuseipdb_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("ABUSEIPDB_TIMEOUT_SECONDS", "2.0"))
    )
    cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIEM_ENRICHMENT_CACHE_TTL_SECONDS", "21600"))
    )
    malicious_score_threshold: int = field(
        default_factory=lambda: int(os.getenv("SIEM_MALICIOUS_SCORE_THRESHOLD", "60"))
    )


@dataclass(slots=True)
class CorrelationConfig:
    rules_file: Path = field(
        default_factory=lambda: Path(
            os.getenv("SIEM_CORRELATION_RULES_PATH", str(RULES_DIR / "correlation_rules.yml"))
        )
    )


@dataclass(slots=True)
class PipelineConfig:
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    suspicious_ip: SuspiciousIPConfig = field(default_factory=SuspiciousIPConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    rules_file: Path = field(
        default_factory=lambda: Path(
            os.getenv("SIEM_RULES_PATH", str(RULES_DIR / "default_rules.yml"))
        )
    )
    anomaly_window_seconds: int = 60
    anomaly_baseline_windows: int = 5
    anomaly_min_events: int = 12
    anomaly_spike_multiplier: float = 3.0
