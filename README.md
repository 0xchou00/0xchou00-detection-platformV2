# 0xchou00-detection-platformV2

## 1. Purpose of the Project

This project is a small distributed detection platform built to teach and demonstrate how a real event pipeline works: log collection, queueing, normalization, stateful detection, correlation, alert routing, and analyst visibility.

The architecture exists because a single-process design cannot explain or test failure boundaries clearly. In this platform, ingestion, processing, storage, alert delivery, and visualization are separate components. That separation makes the control flow explicit and lets a user reason about what happens when one part fails.

## 2. System Overview

The pipeline is:

`lab target or host logs -> agent -> ingest API -> Redis Streams -> backend worker -> PostgreSQL -> alert worker / WebSocket -> dashboard`

From ingestion to alert:

1. A log line is written by SSH, nginx, or the connection logger in the lab target.
2. The agent tails the file and sends batches to `POST /ingest`.
3. The API authenticates the request and appends each line to a Redis stream.
4. The backend worker reads the stream, normalizes the line, stores the event, runs detection, runs correlation, stores any alerts, and appends integrity-chain entries.
5. Alerts are published to the dashboard via WebSocket and routed to the alert stream for webhook or email delivery.

## 3. Architecture

![Architecture](docs/architecture.svg)

### Agent

Responsibilities:

- Tail configured log files.
- Track inode and offset state across restarts.
- Batch events by source type.
- Spool failed deliveries to disk and retry with backoff.

Data flow:

- Reads local files.
- Sends JSON batches to `/ingest`.

Failure behavior:

- If the API is down, unsent batches remain in the spool file.
- If the spool reaches its configured cap, oldest unsent items are discarded.

### Redis Streams

Responsibilities:

- Decouple ingestion from processing.
- Hold queued raw log lines and queued alert deliveries.

How used:

- `siem:ingest` stores raw lines.
- `siem:alerts` stores alert payloads for delivery.

Failure behavior:

- If Redis is down, ingestion fails immediately.
- Workers leave failed messages pending because they `XACK` only after success.
- The current code does not reclaim orphaned pending entries automatically.

### Workers

Responsibilities:

- `backend-worker`: normalize, detect, correlate, persist, publish.
- `alert-worker`: deliver high and critical alerts to SMTP and webhook targets.

Failure behavior:

- A failed message stays pending in Redis Streams.
- There is no dead-letter queue and no `XCLAIM`/`XAUTOCLAIM` recovery loop yet.

### Normalization Layer

Responsibilities:

- Convert raw log text into a common event shape.

Supported sources:

- SSH auth logs
- nginx or Apache access logs
- firewall-style connection logs

Failure behavior:

- Unknown formats return no event and are dropped by the worker.

### Detection Engine

Responsibilities:

- Run built-in detectors for brute force, port scan, and success-after-failures.
- Execute compiled YAML rules with Redis-backed state.

Failure behavior:

- Redis state loss resets windows and dedupe keys.
- Rule files are reloaded by modification time and are not schema-validated before use.

### Correlation Engine

Responsibilities:

- Track recent detector alerts per source IP.
- Promote ordered sequences into higher-level alerts.

Failure behavior:

- Correlation history is transient and Redis-backed.
- A Redis restart clears the sequence state.

### Storage (PostgreSQL)

Responsibilities:

- Persist events, alerts, integrity-chain entries, and API keys.

Failure behavior:

- If PostgreSQL is unavailable, workers do not ack the corresponding stream entry.
- The queue absorbs the backlog until Redis retention becomes a problem.

### API Layer

Responsibilities:

- Authenticate API clients.
- Queue incoming log lines.
- Expose stored events, alerts, correlations, and integrity checks.

Failure behavior:

- The API depends on Redis for ingestion and health backlog reporting.
- It depends on PostgreSQL for historical queries.

### WebSocket System

Responsibilities:

- Push live events and alerts to the dashboard.

Failure behavior:

- It uses Redis Pub/Sub, which is not durable.
- A disconnected dashboard misses anything published while it is offline.

### Dashboard

Responsibilities:

- Show current counts.
- Show live alerts.
- Show correlations and a timeline.
- Support filtering by IP, severity, rule, and free text.

Failure behavior:

- The dashboard is an observer of API and WebSocket state, not a source of truth.

## 4. Data Pipeline (Step-by-step)

1. A service on the lab target writes a log line.
2. The agent reads the line from the shared log volume.
3. The agent buffers the line by source type and sends it to the API.
4. The API appends the line to `siem:ingest`.
5. The backend worker reads the stream entry via `XREADGROUP`.
6. The worker normalizes the line into a typed event.
7. The worker stores the event in PostgreSQL and adds an integrity-chain entry.
8. The worker runs built-in detectors and YAML rules.
9. Any detector alert is stored in PostgreSQL and linked into the integrity chain.
10. The correlation engine updates per-IP state in Redis and checks for rule sequences.
11. Any correlation alert is stored in PostgreSQL and linked into the integrity chain.
12. The worker publishes live event and alert payloads to Redis Pub/Sub.
13. The worker appends alert payloads to `siem:alerts`.
14. The alert worker reads `siem:alerts` and forwards high and critical alerts to configured outputs.

## 5. Detection Engine

Rule format:

- YAML rules define metadata, source scoping, matchers, and optional aggregation.
- Matchers support `equals`, `contains`, and `regex`.
- Aggregation supports `count` and `distinct_count`.

Compilation strategy:

- Rules are parsed into compiled matcher objects.
- Each event is flattened into a dictionary.
- Every rule is evaluated sequentially against that payload.

Execution model:

- Built-in detectors run first.
- YAML rules run second.
- Stateful thresholds use Redis sorted sets keyed by namespace and source group.

Threshold logic:

- A rule fires only after the current window count reaches or exceeds its threshold.
- Dedup buckets suppress repeated alerts for the same rule/group/window slice.

Time windows:

- Windows are based on the normalized event timestamp, not arrival time.
- Delayed logs can therefore affect window placement.

Limitations:

- Sigma support is only a small subset.
- Regex evaluation is linear in rule count.
- Redis restart clears detection state.

## 6. Correlation Engine

State handling:

- Recent detector alerts are stored in Redis sorted sets keyed by `source_ip`.

Attack chain logic:

- A correlation rule defines an ordered sequence of detector stages.
- Matching walks the per-IP history in chronological order.
- If the full sequence appears within the configured window, a correlation alert is emitted.

Example:

- `port_scan -> brute_force -> session_state`
- The self-contained lab is configured so a port scan, repeated SSH failures, and a final SSH success can all originate from the same source IP and trigger this rule.

## 7. Integrity Model

Each event and alert contributes a forward-linked chain entry.

Stored per chain record:

- `payload_hash`
- `prev_hash`
- `related_hashes`
- `contract_hash`

Verification checks:

- chain linkage continuity
- recomputed contract hash correctness
- recomputed entity payload hash correctness

Performance trade-offs:

- Verification is linear in the number of scanned entries.
- The API therefore exposes a `limit` parameter.
- This proves internal database consistency, not external provenance.

## 8. Scalability & Performance

Main bottlenecks:

- Redis for queueing, state, and live transport
- PostgreSQL write throughput
- Worker CPU for regex and JSON serialization

Why Redis Streams:

- It provides ordered append, blocking reads, and consumer groups with little setup overhead.
- It is sufficient for a lab-scale deployment.

Worker scaling model:

- Multiple workers can join the same consumer group.
- Each stream message is processed by one consumer at a time.

DB considerations:

- PostgreSQL stores full JSON payloads plus indexed scalar query fields.
- There is no partitioning or retention policy yet.

Known limits:

- Pending entries are not reclaimed automatically.
- Pub/Sub is not durable.
- Query endpoints are recent-history oriented, not archival search endpoints.

## 9. Failure Scenarios

### Redis down

- `/ingest` fails.
- `/health` backlog reporting fails.
- Detection and correlation state disappears.
- WebSocket live updates stop.

### PostgreSQL down

- Workers cannot persist events or alerts.
- Stream entries remain unacked.
- API query endpoints fail.

### Agent disconnected

- No new local log lines reach the platform.
- Buffered/spooled batches remain on disk.
- Recovery resumes from saved offsets and spool data.

## 10. Home Lab Setup

The repository now includes a self-contained lab target in Docker:

- `lab-target`: runs SSH, nginx, and a TCP connection logger that emits firewall-style logs
- `agent`: tails the target logs and forwards them
- `backend-api`, `backend-worker`, `alert-worker`, `redis`, `postgres`, `dashboard`

Default ports:

- Dashboard: `5173`
- API: `8000`
- Lab target SSH: `2222`
- Lab target HTTP: `8081`
- Lab target connection-logger ports: `2201-2208`

Attack simulation:

- HTTP probing hits sensitive web paths and suspicious user-agents.
- Port scan opens connections across monitored ports.
- SSH brute force uses a short wordlist that ends with the known lab password.

## 11. Quick Start

Minimal commands:

```bash
git clone https://github.com/0xchou00/0xchou00-detection-platformV2.git
cd 0xchou00-detection-platformV2
chmod +x setup.sh run.sh test.sh scripts/lab/*.sh
./setup.sh
./run.sh
./test.sh
```

What you should see:

- `./run.sh` reports API, dashboard, and lab target addresses.
- `./test.sh` prints live alert counts from the backend API.
- The dashboard at `http://127.0.0.1:5173` shows new alerts, timeline entries, and correlation items.

How to verify quickly:

```bash
curl -H "X-API-Key: siem-viewer-dev-key" http://127.0.0.1:8000/alerts?limit=10
curl -H "X-API-Key: siem-viewer-dev-key" http://127.0.0.1:8000/correlations?limit=10
```

## 12. Design Trade-offs

What was simplified:

- One Redis instance serves as queue, state store, and live pub/sub hub.
- Docker Compose is used instead of an orchestrator.
- The lab target is intentionally local and deterministic.

What is not production-ready:

- No pending-entry reclaimer or dead-letter queue.
- No TLS termination in the default stack.
- No secret manager.
- No retention or archival controls.
- No full Sigma support.

What would change at scale:

- Separate queueing from transient state.
- Add replay-safe message recovery.
- Move long-term event storage to a store designed for larger log volume.
- Add rule validation and CI checks.

## 13. Future Improvements (REALISTIC ONLY)

- Add `XPENDING`/`XAUTOCLAIM` handling for abandoned stream entries.
- Add healthchecks and readiness checks for every service.
- Add retention policies for PostgreSQL and Redis streams.
- Add more parsers for additional telemetry sources.
- Add delivery status tracking for outbound alerts.

## Expected Output

After `./test.sh`, a normal successful run should produce:

- brute-force alerts from repeated SSH failures
- port-scan alerts from monitored port connections
- web probe alerts from repeated sensitive HTTP paths
- at least one correlation alert when the ordered sequence is satisfied

If the stack is healthy, those alerts are visible in two places:

- API responses from `/alerts` and `/correlations`
- dashboard live stream and timeline

## Troubleshooting

### `docker: permission denied`

- Run `sudo usermod -aG docker "$USER"` and re-login, or run the scripts with `sudo`.

### `./run.sh` starts but API never becomes ready

- Check `docker compose logs -f backend-api backend-worker postgres redis`.

### `./test.sh` completes but no alerts appear

- Check `docker compose logs -f agent backend-worker lab-target`.
- Confirm the agent is reading `/logs/auth.log`, `/logs/nginx/access.log`, and `/logs/firewall.log`.
- Confirm the API responds to:

```bash
curl -H "X-API-Key: siem-viewer-dev-key" http://127.0.0.1:8000/health
```

### Dashboard opens but live stream stays empty

- Refresh once after `./test.sh`.
- Check WebSocket connectivity in the browser and backend logs.
- Query `/alerts` directly to distinguish UI issues from pipeline issues.
