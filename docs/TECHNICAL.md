# 0xchou00 — Lightweight Security Detection Tool

Technical notes for the standalone detection stack.

## Architecture

`0xchou00 — Lightweight Security Detection Tool` is a single-node detection pipeline with six ordered stages:

1. raw log ingestion
2. normalization
3. IP enrichment
4. first-order detection
5. alert correlation
6. storage and integrity verification

The backend is a FastAPI process. State is local to one process and one SQLite database.
The optional agent tails host log files and forwards batches to `POST /ingest`.

## Detection logic

### SSH brute force

The brute-force detector only evaluates normalized SSH failure events.
It keeps a deque of timestamps per source IP and removes timestamps older than the configured window.
When the number of failures inside the window reaches the threshold, it emits an alert.
If the same source continues and the count grows, the detector emits a fresh alert only when the observed window size changes.

### Web anomalies

The web detector operates on normalized HTTP request events.
It tracks three behaviors:

- request rate per source IP in a bounded window
- HTTP error ratio per source IP
- direct access to high-signal paths such as `/.env`, `/phpmyadmin`, and `/wp-login.php`

These checks are kept separate because each has different evidence and false-positive characteristics.

### Port scanning

The port-scan detector consumes normalized firewall or network connection events.
For each source IP, it keeps a bounded window of `(timestamp, destination_port)` tuples.
The detector alerts when the number of distinct destination ports inside the window reaches the configured threshold.

The detector is intentionally based on distinct-port count rather than raw event count.
That makes it resilient to repeated retries against one port and more aligned with reconnaissance behavior.

### YAML rule engine

The YAML rule engine extends the built-in detectors without modifying Python code.
Rule matching supports:

- exact equality
- substring match
- regular expressions

Aggregation supports:

- `count`
- `distinct_count`

The aggregation window is bounded and grouped on an explicit field such as `source_ip`.
This keeps rule behavior predictable and avoids hidden global state.

### Frequency anomaly

The anomaly detector is deterministic.
It keeps a rolling count history per `(source_type, source_ip)` key and compares the current bucket to the average of previous buckets.
If the current bucket exceeds both the minimum event count and the configured multiplier over baseline, it emits an alert.

This is not model inference and does not depend on training data.

## Enrichment logic

Enrichment is applied after normalization and before detector evaluation.
The current event schema carries:

- `country`
- `risk_score`
- `enrichment_source`
- `threat_labels`

### GeoIP

GeoIP uses a local MaxMind-compatible database when present.
The lookup is read-only and synchronous because it is local.
If the database is missing, the pipeline continues without country data.

### Threat intelligence

Threat intelligence is layered:

1. static file-based blacklist
2. cached external lookup

The static blacklist is local and deterministic.
If a source IP matches the blacklist, the event receives the highest risk score immediately.

The optional AbuseIPDB lookup is asynchronous and cached in SQLite.
The ingest path does not block waiting on every remote request.

## Correlation

Correlation runs on stored detector alerts, not on raw logs.
This is a deliberate separation:

- first-order detectors remain source-aware and simple
- correlation only reasons over alert combinations

Rules are defined in `backend/rules/correlation_rules.yml`.
Each rule declares:

- the detectors that must be present
- the time window
- whether the alerts must share a source IP
- the emitted title, description, and severity

The shipped rule set includes:

- SSH brute force plus port scan
- frequency anomaly plus sensitive path access

## Integrity model

The integrity layer uses a contract-style hash chain.
Each persisted log or alert generates one chain entry with:

- entity type
- entity identifier
- payload hash
- related entity hashes
- previous contract hash
- current contract hash

Logs typically have no related entities.
Detector alerts link to the log entries they were derived from.
Correlated alerts link to the detector alerts that justified the correlation.

The contract hash is computed from the payload hash, the related hashes, the previous contract hash, and the creation timestamp.
Verification replays the chain in order and checks:

- previous-hash linkage
- contract hash recomputation
- current payload hash versus stored payload hash
- current related-entity contract hashes versus stored related hashes

This design does not make the database immutable.
It makes post-write tampering detectable and preserves explicit derivation links between logs and alerts.

## Design decisions

### Why FastAPI

The API surface is small and synchronous enough that FastAPI keeps the code readable without additional service layers.

### Why SQLite

SQLite keeps deployment local and simple.
The tool is meant for one node, not a distributed analytics cluster.

### Why file-based blacklist first

Static threat data is cheap, local, and reliable.
It should influence scoring before any optional network lookup.

### Why separate port-scan detection from web anomaly detection

Port scans and HTTP probing are operationally different activities.
Keeping them in separate detectors preserves better evidence and cleaner correlation.

## Limitations

- Single-node only.
- Detector state is in-process and not shared across workers.
- The Docker path runs the API only unless an operator adds explicit log mounts and an agent runtime.
- GeoIP depends on a local database file being present.
- AbuseIPDB enrichment is optional and best-effort.
- Port-scan detection depends on firewall-style logs or equivalent normalized network events.
