# 0xchou00 - Lightweight Security Detection Tool

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

## Linux (Debian / Ubuntu / Kali)

Tested on:

- Debian
- Ubuntu
- Kali Linux

Step-by-step installation:

```bash
git clone https://github.com/0xchou00/0xchou00-Detection-.git
cd 0xchou00-Detection-
git checkout fix/linux-compatibility
chmod +x setup.sh run.sh scripts/install.sh
./setup.sh
./run.sh
```

Service-based setup (systemd):

```bash
./scripts/install.sh
sudo systemctl start 0xchou00.service
sudo systemctl start 0xchou00-agent.service
```

Run options:

```bash
# Backend only
./run.sh --backend-only

# Backend + dashboard + log agent
./run.sh --with-agent
```

Common errors and fixes:

- `python3: command not found`
  - install Python runtime: `sudo apt-get install -y python3 python3-venv python3-pip`
- `npm: command not found`
  - install Node/npm: `sudo apt-get install -y nodejs npm`
- `Dashboard dependencies are missing`
  - run `./setup.sh` to install `dashboard/node_modules`
- `Permission denied` when running scripts
  - run `chmod +x setup.sh run.sh scripts/install.sh`
- Dashboard CORS request blocked
  - verify `SIEM_ALLOWED_ORIGINS` in `.env` contains your dashboard URL

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
