from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from redis.asyncio import Redis

from app.v2.config import settings
from app.v2.detection import DetectionEngine
from app.v2.normalizer import Normalizer


async def run(samples_file: Path, source_type: str) -> int:
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    normalizer = Normalizer()
    detector = DetectionEngine(redis_client, settings.yaml_rules_path)
    payload = json.loads(samples_file.read_text(encoding="utf-8"))
    lines = payload.get("lines", [])
    total_alerts = 0
    for line in lines:
        event = normalizer.normalize(source_type, line)
        if not event:
            continue
        event.timestamp = datetime.now(timezone.utc)
        alerts = await detector.run(event)
        total_alerts += len(alerts)
        for alert in alerts:
            data = alert.to_dict()
            print(json.dumps({"id": data["id"], "rule_id": data["rule_id"], "title": data["title"]}))
    await redis_client.aclose()
    return total_alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute rule tests against sample logs.")
    parser.add_argument("--samples", required=True, help="Path to JSON file: {\"lines\": [...]} ")
    parser.add_argument("--source-type", required=True, choices=["ssh", "nginx", "apache", "web", "firewall", "network"])
    args = parser.parse_args()
    alerts = asyncio.run(run(Path(args.samples), args.source_type))
    print(f"total_alerts={alerts}")


if __name__ == "__main__":
    main()

