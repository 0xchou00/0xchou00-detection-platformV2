from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.v2.config import settings  # noqa: E402
from app.v2.correlation import CorrelationEngine  # noqa: E402
from app.v2.detection import DetectionEngine, RuleCompiler  # noqa: E402
from app.v2.normalizer import Normalizer  # noqa: E402
from app.v2.state import InMemoryStateStore  # noqa: E402


CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


def _load(name: str) -> list[dict]:
    payload = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    return list(payload.get("entries", []))


async def _run_entries(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    state = InMemoryStateStore()
    normalizer = Normalizer()
    detector = DetectionEngine(state, settings.yaml_rules_path)
    correlator = CorrelationEngine(state, settings.correlation_rules_path)
    alerts: list[dict] = []
    correlations: list[dict] = []

    for entry in entries:
        parsed = normalizer.normalize(entry["source_type"], entry["line"])
        event = parsed.event
        event.timestamp = datetime.fromisoformat(entry["timestamp"]).astimezone(timezone.utc)
        if entry.get("enrichment"):
            event.metadata["enrichment"] = entry["enrichment"]
        detector_alerts = await detector.run(event)
        for alert in detector_alerts:
            alerts.append(alert.to_dict())
            for correlated in await correlator.run(alert):
                correlations.append(correlated.to_dict())
    return alerts, correlations


def test_rule_schema_compiles() -> None:
    compiler = RuleCompiler(settings.yaml_rules_path)
    assert compiler.rules
    assert all(rule.rule_id for rule in compiler.rules)
    correlator = CorrelationEngine(InMemoryStateStore(), settings.correlation_rules_path)
    assert correlator is not None


def test_attack_chain_replay() -> None:
    alerts, correlations = asyncio.run(_run_entries(_load("ssh_attack_chain.json")))
    rule_ids = {item["rule_id"] for item in alerts}
    correlation_ids = {item["rule_id"] for item in correlations}
    assert "builtin_port_scan" in rule_ids
    assert "builtin_ssh_bruteforce" in rule_ids
    assert "builtin_success_after_failures" in rule_ids
    assert "scan_to_bruteforce_to_success" in correlation_ids


def test_distributed_attack_detection() -> None:
    alerts, _ = asyncio.run(_run_entries(_load("distributed_auth_attack.json")))
    rule_ids = {item["rule_id"] for item in alerts}
    assert "builtin_single_username_many_ips" in rule_ids


def test_false_positive_corpus_stays_quiet() -> None:
    alerts, correlations = asyncio.run(_run_entries(_load("normal_traffic.json")))
    severities = {item["severity"] for item in alerts + correlations}
    assert severities <= {"info", "low", "medium"}
    assert "critical" not in severities
    assert "high" not in severities


def test_low_and_slow_evasion_does_not_cross_threshold() -> None:
    alerts, correlations = asyncio.run(_run_entries(_load("low_and_slow.json")))
    rule_ids = {item["rule_id"] for item in alerts + correlations}
    assert "builtin_ssh_bruteforce" not in rule_ids
    assert "scan_to_bruteforce_to_success" not in rule_ids


def test_malformed_logs_remain_parse_failures() -> None:
    normalizer = Normalizer()
    for entry in _load("malformed_logs.json"):
        parsed = normalizer.normalize(entry["source_type"], entry["line"])
        assert parsed.parsed is False
        assert parsed.event.parser_status == "failed"
        assert parsed.event.event_type == "unparsed_log"
        assert parsed.event.raw_message == entry["line"]


def test_delayed_logs_can_be_replayed_by_event_time() -> None:
    alerts, _ = asyncio.run(_run_entries(_load("delayed_web_probe.json")))
    rule_ids = {item["rule_id"] for item in alerts}
    assert "web_sensitive_probe" in rule_ids
    assert "web_suspicious_user_agent" in rule_ids


def test_replayed_logs_are_deduplicated() -> None:
    alerts, correlations = asyncio.run(_run_entries(_load("replayed_logs.json")))
    rule_ids = [item["rule_id"] for item in alerts + correlations if item.get("rule_id")]
    assert rule_ids.count("web_command_injection_pattern") == 1
    assert rule_ids.count("web_server_error_burst") == 0


def test_partial_telemetry_blocks_attack_chain_correlation() -> None:
    alerts, correlations = asyncio.run(_run_entries(_load("partial_telemetry.json")))
    assert any(item["rule_id"] == "builtin_ssh_bruteforce" for item in alerts)
    assert all(item["rule_id"] != "scan_to_bruteforce_to_success" for item in correlations)
