from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.v2.config import settings
from app.v2.correlation import CorrelationEngine
from app.v2.detection import DetectionEngine
from app.v2.normalizer import Normalizer
from app.v2.state import InMemoryStateStore


async def run(samples_file: Path) -> int:
    payload = json.loads(samples_file.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    state = InMemoryStateStore()
    normalizer = Normalizer()
    detector = DetectionEngine(state, settings.yaml_rules_path)
    correlator = CorrelationEngine(state, settings.correlation_rules_path)
    total_alerts = 0

    for entry in entries:
        source_type = str(entry["source_type"])
        line = str(entry["line"])
        parse = normalizer.normalize(source_type, line)
        event = parse.event
        if entry.get("timestamp"):
            event.timestamp = datetime.fromisoformat(entry["timestamp"]).astimezone(timezone.utc)
        if entry.get("enrichment"):
            event.metadata["enrichment"] = entry["enrichment"]
        alerts = await detector.run(event)
        for alert in alerts:
            data = alert.to_dict()
            print(json.dumps({"id": data["id"], "rule_id": data["rule_id"], "title": data["title"]}))
            total_alerts += 1
            correlated = await correlator.run(alert)
            for corr in correlated:
                corr_data = corr.to_dict()
                print(json.dumps({"id": corr_data["id"], "rule_id": corr_data["rule_id"], "title": corr_data["title"]}))
                total_alerts += 1
    return total_alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute detection and correlation replay tests against a corpus file.")
    parser.add_argument("--samples", required=True, help="Path to JSON file with {\"entries\": [...]} records.")
    args = parser.parse_args()
    alerts = asyncio.run(run(Path(args.samples)))
    print(f"total_alerts={alerts}")


if __name__ == "__main__":
    main()
