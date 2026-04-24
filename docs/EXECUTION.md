# EXECUTION GUIDE - 0xchou00 Detection Platform V2

## 1. Environment Requirements

Supported operating systems:

- Kali Linux, primary target
- Ubuntu or Debian, secondary target

Virtualization:

- VMware Workstation or VirtualBox
- Recommended lab sizing:
  - Minimum: 8 GB RAM, 4 CPU cores, 40 GB disk
  - Recommended: 16 GB RAM, 6 to 8 CPU cores, 80 GB disk

Why these resources matter:

- Docker, PostgreSQL, Redis, the API, workers, the dashboard, and the lab target all run at the same time.
- The attack simulation opens SSH, HTTP, and scan traffic at the same time as ingestion and detection.
- Lower RAM causes PostgreSQL and the dashboard to compete with the workers, which makes startup and alert delivery unstable.

Required tools:

- `docker` or `docker.io`
- `docker compose` or `docker-compose`
- `git`
- `curl`
- `python3`

Why each tool is required:

- Docker runs the full platform in containers.
- Compose starts the multi-service stack in one command.
- Git clones the repository.
- Curl verifies API health and fetches results.
- Python 3 is used by the backend scripts, tests, and helper utilities.

## 2. Pre-flight Check

Run these commands before setup:

```bash
docker --version
docker compose version
docker-compose --version
curl --version
python3 --version
free -h
df -h
```

What to verify:

- Docker prints a version and not an error.
- At least one compose command works: `docker compose` or `docker-compose`.
- Memory is at or above the minimum listed above.
- Disk has enough free space for images, packages, and container logs.

If Docker is missing on Kali, Debian, or Ubuntu, install it with the project setup script:

```bash
./setup.sh
```

If compose is missing after setup, the script will try the OS package first and then fall back to the Python package.

## 3. Clone and Setup

Clone the repository:

```bash
git clone https://github.com/0xchou00/0xchou00-detection-platformV2.git
cd 0xchou00-detection-platformV2
```

Run setup:

```bash
./setup.sh
```

What `./setup.sh` does internally:

- Detects the host OS from `/etc/os-release`
- Supports Kali Linux, Debian, and Ubuntu
- Creates `.env` from `.env.example` if it does not exist
- Installs system dependencies:
  - Docker runtime
  - Compose
  - Git
  - Curl
  - Python 3
  - Node.js tooling
  - Nmap
  - Hydra
  - OpenSSH client
- Creates a Python virtual environment
- Installs Python dependencies from `requirements.txt`
- Installs dashboard Node dependencies
- Creates the local `logs/` directory and lab support directories

Edge cases handled by setup:

- Kali Linux compose packaging:
  - `setup.sh` prefers `docker.io` plus `docker-compose`
  - if the OS repository does not provide `docker-compose`, it falls back to `python3 -m pip install --user docker-compose`
- Missing `.env`:
  - `setup.sh` copies `.env.example` to `.env` automatically

## 4. Running the Platform

Start the full system:

```bash
./run.sh
```

What starts:

- PostgreSQL
- Redis
- Backend API
- Backend worker
- Alert worker
- Dashboard
- Lab target container
- Agent

What each service does:

- PostgreSQL stores events, alerts, audit records, and integrity-chain records.
- Redis holds the ingest stream, alert stream, dead-letter stream, and short-lived state.
- Backend API receives telemetry, authenticates agents, and serves alert and event queries.
- Backend worker consumes logs, normalizes them, enriches them, detects events, and writes results.
- Alert worker delivers high-severity alerts to external targets.
- Dashboard shows live alerts, correlations, and failed parser events.
- Lab target generates the SSH and web telemetry used by the attack simulation.
- Agent tails the lab target logs and sends signed batches to the API.

## 5. Verifying System Health

Check container status:

```bash
docker compose ps
```

View backend API logs:

```bash
docker compose logs -f backend-api
```

Check API health:

```bash
curl -H "X-API-Key: siem-viewer-dev-key" http://localhost:8000/health
```

What “healthy” means:

- Docker containers are running and not crash-looping
- PostgreSQL and Redis have passed their health checks
- The API answers `/health`
- The backend worker is consuming the ingest stream
- The dashboard can connect to the API

If the API does not answer, inspect the service logs before retrying.

## 6. Attack Simulation Scenario

Run the test scenario:

```bash
./test.sh
```

What the test does:

1. HTTP probing
   - sends repeated requests to the lab target web service
   - produces nginx access log entries
   - can trigger suspicious user-agent and probing detections

2. Port scanning
   - scans the lab target’s monitored ports
   - produces connection and firewall-style telemetry
   - can trigger scan and port-abuse detections

3. SSH brute force
   - attempts repeated SSH logins against the lab target
   - produces authentication failures in the SSH log
   - can trigger brute-force and correlation rules

What logs are generated:

- nginx access logs
- SSH authentication logs
- container and target service logs
- firewall-style port activity from the lab target

## 7. Pipeline Explanation

Internal flow during the test:

### Agent

- reads new lines from the lab target log files
- batches lines by source
- signs the request with the configured API key and HMAC
- sends the batch to the backend API

### API

- validates the agent identity
- checks HMAC, nonce, timestamp, and rate limit
- appends each accepted line to the Redis ingest stream

### Workers

- read from Redis Streams through consumer groups
- reclaim stuck messages using `XPENDING` and `XAUTOCLAIM`
- normalize each line into a structured event
- enrich the event with context
- run detection rules
- run correlation rules
- persist the event and alert records into PostgreSQL

### Storage

- PostgreSQL stores the durable event and alert history
- failed parses are also stored instead of being dropped
- dead-letter records remain inspectable through the API

## 8. Observing Results

Open the dashboard:

```text
http://localhost:5173
```

What to look for:

- live alerts arriving in the stream
- severity values changing with the detection type
- correlation events that group a scan, brute-force, and success sequence
- parser-failed events for malformed or unknown logs

Validate through the API:

```bash
curl -H "X-API-Key: siem-viewer-dev-key" "http://localhost:8000/alerts"
```

Expected output:

- a JSON response containing alert objects
- rule names
- source IP addresses
- severity values
- timestamps

Useful additional checks:

```bash
curl -H "X-API-Key: siem-viewer-dev-key" "http://localhost:8000/correlations"
curl -H "X-API-Key: siem-viewer-dev-key" "http://localhost:8000/events?parser_status=failed"
curl -H "X-API-Key: siem-viewer-dev-key" "http://localhost:8000/dead-letters"
```

## 9. Failure Scenarios

If Redis is down:

- ingest fails
- workers cannot read or acknowledge messages
- live dashboard updates stop
- the agent relies on its local spool until Redis returns

Diagnose:

```bash
docker compose ps
docker compose logs -f redis backend-worker alert-worker
```

If PostgreSQL is down:

- events and alerts cannot be persisted
- API query endpoints fail
- workers keep messages pending until storage returns

Diagnose:

```bash
docker compose ps
docker compose logs -f postgres backend-api backend-worker
```

If the agent stops:

- no new telemetry is sent
- local log offsets are preserved
- the agent resumes from the last offset on restart

Diagnose:

```bash
docker compose logs -f agent
```

If a worker crashes:

- the message remains pending in Redis Streams
- `XAUTOCLAIM` can recover it after the idle timeout
- retry counts increase
- poison messages move to the dead-letter stream

Diagnose:

```bash
docker compose logs -f backend-worker alert-worker
docker compose logs -f redis
```

## 10. Cleanup

Stop the platform:

```bash
docker compose down
```

Optional cleanup of unused Docker objects:

```bash
docker system prune -f
```

## 11. Notes on Behavior

- The dashboard depends on the backend API being healthy.
- The pipeline is designed to keep malformed or unknown logs instead of dropping them.
- Dead-letter records exist so failed messages are inspectable later.
- The runbook assumes the repository has already been cloned and `./setup.sh` has completed successfully.
