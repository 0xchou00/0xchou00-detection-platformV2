# Technical Deep Dive

## Runtime Topology

Default runtime processes:

- `lab-target`: local attack surface for SSH, HTTP, and firewall-style connection logs.
- `agent`: tails lab-target logs and forwards them to the API.
- `backend-api`: FastAPI application serving ingestion, query APIs, and WebSocket fan-out.
- `backend-worker`: stream consumer that performs normalization, detection, correlation, persistence, and live publication.
- `alert-worker`: stream consumer that routes stored alert payloads to email and webhook sinks.
- `redis`: backs streams, detection state, correlation state, dedupe keys, and Pub/Sub.
- `postgres`: backs durable tables and integrity-chain records.
- `dashboard`: browser client backed by HTTP bootstrap queries and WebSocket updates.

The project uses one Redis instance for four distinct roles:

1. Ingest queue
2. Alert queue
3. Detection and correlation state store
4. Pub/Sub hub for live UI updates

This is operationally convenient and easy to inspect in a lab, but it means one Redis outage removes queueing, state, and live transport at once.

The default repository path is self-contained: `./run.sh` starts every component needed to exercise the pipeline, including a lab target and an agent. The standalone agent config still exists for non-containerized deployments.

## Internal Data Models

### `NormalizedEvent`

Defined in [backend/app/v2/normalizer.py](</C:/Users/omarc/Desktop/version final detection tool/0xchou00-Detection-/backend/app/v2/normalizer.py>).

Fields:

- `timestamp`
- `source_type`
- `event_type`
- `raw_message`
- `severity`
- `source_ip`
- `destination_ip`
- `destination_port`
- `metadata`

`metadata` carries parser-specific attributes. Current parsers populate:

- SSH: `username`, `status`
- HTTP: `method`, `path`, `status`, `user_agent`
- Firewall: `protocol`, `status`

### `events` table

Defined in [backend/app/v2/db.py](</C:/Users/omarc/Desktop/version final detection tool/0xchou00-Detection-/backend/app/v2/db.py>).

Columns:

- `id`
- `timestamp`
- `received_at`
- `source_type`
- `event_type`
- `source_ip`
- `destination_ip`
- `destination_port`
- `severity`
- `raw_message`
- `payload` (`JSONB`)
- `integrity_hash`

`timestamp` is derived from the source log. `received_at` is assigned by the API before the line enters Redis Streams.

### `Alert`

Defined in [backend/app/v2/detection.py](</C:/Users/omarc/Desktop/version final detection tool/0xchou00-Detection-/backend/app/v2/detection.py>).

Fields:

- `detector`
- `severity`
- `title`
- `description`
- `source_type`
- `source_ip`
- `event_count`
- `evidence`
- `metadata`
- `created_at`
- `alert_id`
- `rule_id`
- `alert_kind`

`alert_kind` distinguishes plain detector alerts from correlation alerts.

### `alerts` table

Columns:

- `id`
- `created_at`
- `detector`
- `rule_id`
- `alert_kind`
- `severity`
- `title`
- `description`
- `source_type`
- `source_ip`
- `event_count`
- `metadata` (`JSONB`)
- `evidence` (`JSONB`)
- `integrity_hash`

The persisted `metadata` is augmented inside the worker to include:

- `related_event_ids`
- `related_alert_ids`

### `integrity_chain` table

Columns:

- `sequence`
- `created_at`
- `entity_type`
- `entity_id`
- `prev_hash`
- `payload_hash`
- `related_hashes`
- `contract_hash`

The chain is append-only by convention, but not enforced by database constraints beyond row insertion semantics.

## Event Schema by Source Type

### SSH

Input pattern:

- failed login
- successful login

Produced event types:

- `authentication_failure`
- `authentication_success`

Severity assignment:

- failure -> `high`
- success -> `info`

### HTTP

Input pattern:

- common access log style with client IP, request line, status, and user-agent

Produced event type:

- `http_request`

Severity assignment:

- status >= 400 -> `medium`
- otherwise -> `info`

### Firewall

Input pattern:

- syslog line containing `SRC=`, `DST=`, `PROTO=`, `DPT=`

Produced event type:

- `network_connection_attempt`

Severity assignment:

- `medium`

## Detection Execution Flow

Entry point: `WorkerPipeline.process()`

Execution order:

1. Normalize raw line into `NormalizedEvent`
2. Persist event to PostgreSQL
3. Append event integrity record
4. Run built-in detections
5. Run YAML detections
6. Persist each detector alert
7. Append alert integrity record
8. Run correlation for each detector alert
9. Persist each correlation alert
10. Append correlation alert integrity record
11. Publish live event/alert payloads
12. Enqueue alert for outbound delivery

Important consequence:

- Event persistence happens before detection.
- If detection fails after the event commit, the event still exists in PostgreSQL even though no alert was created.

## YAML Rule Compilation

The rule compiler loads YAML from `backend/rules/default_rules.yml` and produces `CompiledRule` objects.

Native rule properties:

- `rule_id`
- `title`
- `description`
- `severity`
- `source_type`
- `event_type`
- `matchers`
- `group_by`
- `window_seconds`
- `threshold`
- `function`
- `distinct_field`

Supported matcher operations:

- `equals`
- `contains`
- `regex`

Compilation is intentionally shallow. It does not optimize rules into a decision tree or indexed lookup table. Every rule is evaluated sequentially against each normalized event.

## Sigma-like Subset

The Sigma-like mode is not a full Sigma engine. Current support is limited to:

- `sigma.logsource.product`
- `sigma.detection.selection`

The `condition` field is parsed from the YAML file but not evaluated as a general expression tree. The implementation effectively treats `selection` as the whole condition.

This is enough to demonstrate translation into the internal matcher model, but it is not compatible with most real Sigma rules without preprocessing.

## Detection State Storage

Redis stores two classes of short-lived state.

### Count windows

Key pattern:

- `siem:state:<namespace>:<group>:count`

Stored value:

- Sorted set of synthetic members scored by event timestamp

Usage:

- brute-force failure counts
- YAML `count` aggregations

Window maintenance:

- add member
- trim anything older than `window_seconds`
- count members in current range
- set key expiry to roughly three window lengths

### Distinct windows

Key pattern:

- `siem:state:<namespace>:<group>:distinct`

Stored value:

- Sorted set where the member is the distinct field value and the score is the most recent timestamp

Usage:

- port-scan distinct destination ports
- YAML `distinct_count` aggregations

Trade-off:

- Reusing the distinct value as the member means repeat observations overwrite the member timestamp rather than creating multiple entries. That is correct for distinct counts, but it also means the set captures only the most recent timestamp for each distinct value.

### Dedupe keys

Key pattern:

- `siem:state:dedupe:<rule_id>:<group>:<bucket>`
- `siem:corr:dedupe:<fingerprint>`

Stored value:

- simple string created with `SET NX EX`

Usage:

- suppress repeated alert emission inside a bucket or correlation window

## Built-in Detection Logic

### SSH brute force

Namespace:

- `builtin:ssh_fail`

Logic:

- increment count window for source IP over 120 seconds
- fire when count >= 5
- severity becomes `critical` when count >= 20, otherwise `high`

### Port scan

Namespace:

- `builtin:portscan`

Logic:

- maintain distinct destination ports for source IP over 60 seconds
- fire when distinct count >= 8

### Success after failures

Namespace:

- `builtin:ssh_fail`

Logic:

- on successful SSH authentication, inspect prior failure count over 300 seconds without adding a new member
- fire when recent failures >= 3

## Correlation State Storage

Correlation keeps recent detector alerts in Redis sorted sets.

Key pattern:

- `siem:corr:history:<source_ip>`

Member:

- JSON-serialized alert summary

Score:

- `created_at` Unix timestamp

Retention:

- Trim anything older than two hours
- Expire the key after three hours

Rule evaluation then takes the trimmed history, bounds it again to each rule's `window_seconds`, and performs ordered sequence matching.

Trade-offs:

- Cheap to implement and inspect
- History is duplicated in Redis and PostgreSQL
- PostgreSQL is not used for replay or recovery
- Sequence matching is linear and simple but limited in expressiveness

## Worker Lifecycle

### Startup

`backend-worker`:

1. Connect to Redis
2. Initialize PostgreSQL schema
3. Create ingest consumer group if absent
4. Instantiate `WorkerPipeline`
5. Block on `XREADGROUP`

`alert-worker`:

1. Connect to Redis
2. Create alert consumer group if absent
3. Instantiate `AlertDispatcher`
4. Block on `XREADGROUP`

### Normal processing

- Read a batch from the stream
- Process one message at a time
- Ack only after successful completion

### Failure behavior

- Exceptions are logged
- The message is left pending because `XACK` is not called
- No automatic claim logic exists for orphaned pending entries

This means the current design provides at-least-once intent, but operational recovery of failed or abandoned pending entries is incomplete.

## Message Queue Behavior

### Ingest stream

Producer:

- `POST /ingest`

Payload fields:

- `source_type`
- `line`
- `received_at`
- `agent_id`

Consumer group:

- configured by `SIEM_INGEST_GROUP`

Consumer behavior:

- `XREADGROUP` with `>` only
- `XACK` after successful processing

Retry model:

- implicit only
- failures leave the entry pending
- no dead-letter queue
- no `XPENDING`, `XCLAIM`, or `XAUTOCLAIM`

### Alert stream

Producer:

- `WorkerPipeline._store_alert()`

Payload fields:

- one JSON field named `alert`

Consumer group:

- configured by `SIEM_ALERT_GROUP`

Retry model:

- same as ingest stream

### Pub/Sub channel

Channel:

- configured by `SIEM_LIVE_CHANNEL`

Use:

- push live event and alert notifications to WebSocket clients

Delivery property:

- best effort only
- messages are dropped for disconnected subscribers

## API Behavior

### `POST /ingest`

Behavior:

- validates analyst role
- strips empty lines
- appends each non-empty line independently to Redis Streams
- returns accepted count and queued count

Notable detail:

- it does not validate whether `source_type` is supported by the normalizer

### `GET /events`, `GET /alerts`, `GET /correlations`

Behavior:

- query PostgreSQL directly
- order by newest first
- apply optional filters

Notable detail:

- no cursor pagination
- no query cost guard other than `limit`

### `GET /integrity/verify`

Behavior:

- scans up to `limit` chain records in sequence order
- recomputes chain material and payload hashes

### `WS /ws/live`

Behavior:

- validates viewer key from query string
- subscribes to Redis Pub/Sub
- sends heartbeat every 15 seconds

Notable detail:

- the WebSocket server does not backfill missed messages

## Alert Delivery Flow

Alert delivery is severity-gated:

- `high`
- `critical`

For those severities, the alert worker attempts:

1. Webhook delivery if the corresponding URL is configured
2. SMTP delivery if SMTP host and recipients are configured

Ordering matters because the current code sends the webhook first and email second in the same coroutine. A failure in webhook delivery prevents email delivery for that alert attempt because both are inside one `try` block at the worker level.

## Integrity Verification Flow

For each chain row:

1. Recompute `contract_hash`
2. Check stored `prev_hash` against the previous row
3. Recompute current entity payload hash from PostgreSQL
4. Compare it to stored `payload_hash`

Integrity guarantees are limited to database state consistency. The system does not sign events at the source, so it cannot prove that the raw source log itself was genuine.

## Practical Limits

- Regex-heavy rule sets will scale linearly with rule count.
- Redis state loss resets all sliding windows and correlation memory.
- Pending stream entries require manual intervention or additional automation for full recovery.
- The current schema stores complete JSON payloads in PostgreSQL but does not normalize deep fields for indexed search.
- The dashboard bootstrap queries assume recent-history usage and will need redesign for larger event volumes.
