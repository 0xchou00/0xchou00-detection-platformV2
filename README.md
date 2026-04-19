# 0xchou00 — Lightweight Security Detection Tool

`0xchou00` is a local-first security detection tool with a FastAPI backend and a React SOC dashboard.
The backend ingests SSH, HTTP, and firewall logs, normalizes them into one event model, enriches source IPs, runs bounded detections, correlates related alerts, and records the stored state in a verifiable integrity chain.
The dashboard reads the same backend through `GET /health`, `GET /alerts`, and `GET /logs`.

## Repository layout

- `backend/` FastAPI API, normalization, detection, correlation, storage, and integrity logic
- `backend/rules/` YAML detection rules, correlation rules, and static blacklist data
- `agent/` local tailing agent for auth, nginx, and firewall logs
- `dashboard/` React SOC dashboard
- `docs/` technical notes
- `scripts/` systemd units and Linux install script

## Backend

Features:

- FastAPI ingest and query API
- normalization for SSH, nginx-style HTTP, and firewall-style network logs
- SSH brute-force detection
- suspicious web behavior detection
- port-scan detection
- YAML rule engine with regex and aggregation
- alert correlation
- IP enrichment with local GeoIP, static blacklist data, and optional AbuseIPDB lookups
- SQLite storage
- contract-style integrity verification

Run locally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cd backend
uvicorn main:app --reload
```

API:

- `GET /health`
- `POST /ingest`
- `GET /logs`
- `GET /alerts`
- `GET /integrity/verify`

Viewer key:

```text
siem-viewer-dev-key
```

## Dashboard

Run locally:

```bash
cd dashboard
npm install
npm run dev
```

Default frontend target:

- `http://localhost:8000`

The dashboard polls:

- `GET /health`
- `GET /alerts`
- `GET /logs`

## Example ingest

```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: siem-analyst-dev-key" \
  -d '{
    "source_type": "firewall",
    "lines": [
      "Apr 19 10:00:00 sensor kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=54321 DF PROTO=TCP SPT=41233 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0",
      "Apr 19 10:00:02 sensor kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.50 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=54322 DF PROTO=TCP SPT=41234 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0"
    ]
  }'
```

## Technical notes

See `docs/TECHNICAL.md` for:

- architecture
- detection logic
- enrichment logic
- correlation
- integrity model
- design decisions
- limitations
