# Technical Deep Dive

This document describes the internal contracts behind the V2 hardening phase. It is intentionally implementation-focused.

## Runtime Topology

Default processes:

- `agent`: tails files, buffers locally, signs ingest requests
- `backend-api`: validates ingest requests, appends to Redis Streams, serves query APIs and WebSocket clients
- `backend-worker`: consumes the ingest stream, normalizes, enriches, detects, correlates, persists
- `alert-worker`: consumes the alert stream, sends webhook and SMTP alerts
- `redis`: logical separation for streams, Pub/Sub, and state
- `postgres`: durable events, alerts, audit, credentials, integrity
- `dashboard`: HTTP bootstrap plus WebSocket updates

Redis responsibilities are explicitly separated by logical database:

- DB 0: stream queue only
- DB 1: Pub/Sub only
- DB 2: detection state, correlation state, retry metadata, replay nonces, rate-limit counters

This does not remove the single-instance failure domain. It does remove keyspace mixing and makes intent explicit.

## Internal Data Models

### Normalized event

Defined in `backend/app/v2/normalizer.py`.

Core fields:

- `timestamp`
- `source_type`
- `event_type`
- `raw_message`
- `severity`
- `source_ip`
- `destination_ip`
- `destination_port`
- `metadata`
- `parser_status`
- `parser_error`

Important rule:

- parsing failure does not return `None`
- parsing failure returns a valid event with `parser_status=failed`

### Event record

Defined in `backend/app/v2/db.py` as `EventRecord`.

Important fields:

- `id`
- `received_at`
- `timestamp`
- `agent_id`
- `ingest_source_ip`
- `source_type`
- `event_type`
- `parser_status`
- `parser_error`
- `raw_message`
- `payload`
- `enrichment`
- `integrity_hash`

Partitioning:

- range partitioned by `received_at`
- monthly partitions are created during startup

Indexes:

- source type/time
- source IP/time
- parser status/time
- payload JSONB GIN
- enrichment JSONB GIN
- expression index on `payload->>'ingest_message_id'`

### Alert record

Defined as `AlertRecord`.

Important fields:

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
- `metadata`
- `evidence`
- `integrity_hash`

Partitioning:

- range partitioned by `created_at`

### Ingest audit record

Defined as `IngestAuditRecord`.

Purpose:

- preserve security-relevant ingest failures and accepted queueing decisions

Important fields:

- `created_at`
- `agent_id`
- `source_ip`
- `outcome`
- `reason`
- `details`

### Agent credential record

Defined as `AgentCredentialRecord`.

Purpose:

- bind agent identity to an API key, signing secret, rate limit, and key version

Important fields:

- `agent_id`
- `api_key`
- `signing_secret`
- `key_version`
- `rate_limit_per_window`
- `rotated_from`
- `is_active`
- `last_used_at`

## Event Schema

### Common event shape

All stored events preserve:

- normalized timestamps
- raw log line
- parser status
- parser error metadata when parsing fails
- enrichment context
- top-level metadata copied from parser-specific fields

### SSH events

Event types:

- `authentication_failure`
- `authentication_success`

Metadata:

- `username`
- `status`

### HTTP events

Event type:

- `http_request`

Metadata:

- `method`
- `path`
- `status`
- `user_agent`

### Firewall events

Event type:

- `network_connection_attempt`

Metadata:

- `protocol`
- `status`

### Parse failure events

Event type:

- `unparsed_log`

Metadata contract:

- `raw_message` is always the original line
- `parser_status=failed`
- `parser_error.reason` is at least `no_parser_match`

## Ingest Security Contract

`POST /ingest` expects:

- `X-Agent-Id`
- `X-Agent-Key`
- `X-Key-Version`
- `X-Timestamp`
- `X-Nonce`
- `X-Signature`

Signature material:

`agent_id + "\n" + timestamp + "\n" + nonce + "\n" + key_version + "\n" + sha256(body)`

Signature algorithm:

- HMAC-SHA256 with the active agent signing secret

Validation order:

1. optional TLS requirement
2. required header presence
3. timestamp parse
4. replay window check
5. active agent credential lookup
6. key version check
7. signature verification
8. nonce uniqueness through Redis `SET NX EX`
9. per-agent rate limit through Redis `INCR`

Failure outcome:

- reject request
- write `ingest_audit` record when storage is available

## Worker Lifecycle

### Ingest worker

Startup sequence:

1. connect to stream Redis, Pub/Sub Redis, and state Redis
2. initialize database schema and partitions
3. ensure ingest consumer group exists
4. instantiate `WorkerPipeline`

Main loop:

1. inspect `XPENDING`
2. reclaim stuck messages with `XAUTOCLAIM`
3. read new messages with `XREADGROUP`
4. process each message
5. `XACK` on success
6. increment retry state on failure
7. dead-letter after retry exhaustion

### Alert worker

Startup sequence:

1. connect to stream Redis and state Redis
2. ensure alert consumer group exists
3. instantiate `AlertDispatcher`

Main loop:

1. reclaim stuck alert messages
2. read new alert messages
3. deliver
4. `XACK` on success
5. increment retry state on failure
6. dead-letter after retry exhaustion

## Message Queue Behavior

### Consumer groups

Current groups:

- ingest group: `workers`
- alert group: `alerting`

Streams are consumed with one logical owner per pending entry at a time. Messages are not removed until explicitly acknowledged.

### Pending-entry handling

`XPENDING` is used to inspect queue health.

`XAUTOCLAIM` is used to reclaim messages whose idle time exceeds `SIEM_STREAM_CLAIM_IDLE_MS`.

This means worker death does not leave messages permanently stranded in another consumer.

### Retry model

Retry counters are stored in state Redis:

- key pattern: `siem:retry:<stream>:<message_id>`

Behavior:

- increment on processing failure
- expire the counter after `SIEM_STREAM_RETRY_TTL_SECONDS`
- dead-letter once retry count reaches `SIEM_STREAM_RETRY_LIMIT`

### Dead-letter model

Dead-letter messages are written to `siem:dead-letter`.

Stored fields:

- original stream
- consumer group
- original message ID
- original payload
- failure reason
- retry count
- last processing error
- timestamp
- source agent

Dead letters are inspectable through `GET /dead-letters`.

## Detection Execution Flow

Entry point:

- `WorkerPipeline.process()`

Detailed order:

1. normalize raw line
2. attach ingest metadata such as `agent_id` and `ingest_message_id`
3. enrich with asset, identity, GeoIP, ASN, reputation, suppression
4. store event if it has not already been stored for the same stream message ID
5. append integrity-chain event record
6. run built-in detections
7. run YAML rules
8. store detector alerts
9. append integrity-chain alert records
10. run correlation for each detector alert
11. store correlation alerts
12. append integrity-chain correlation records
13. publish live event and alert updates
14. append alert payloads to the alert stream

Important consequence:

- malformed logs are persisted even when no detection runs
- suppression context can block alert emission without blocking event storage

## Rule Compilation and Validation

Detection rules are validated through Pydantic models:

- field-level regex compilation
- aggregation field validation
- required metadata such as explanation and ATT&CK IDs

Compilation output:

- `CompiledRule`
- `CompiledMatcher`

Supported Sigma-like subset:

- `sigma.logsource.product`
- `sigma.detection.selection`

Unsupported Sigma behaviors:

- general boolean conditions
- field modifiers
- pipelines

## Built-in Detection State

State namespaces:

- `builtin:ssh_fail`
- `builtin:ssh_ip_usernames`
- `builtin:ssh_username_ips`
- `builtin:portscan`

Extra baseline keys:

- `siem:auth:seen_ips:<username>`
- `siem:auth:rare_users`
- `siem:auth:last_login:<username>`

Deduplication keys:

- `siem:state:builtin-dedupe:<rule_id>:<group>:<bucket>`

Purpose:

- built-in detections should not emit on every retry or every additional event within the same bucket

## Correlation State Storage

Key pattern:

- `siem:corr:history:<source_ip>`

Storage type:

- Redis sorted set of JSON summaries

TTL:

- bounded by `SIEM_CORRELATION_HISTORY_TTL_SECONDS`

Dedupe:

- `siem:corr:dedupe:<fingerprint>`

Recovery behavior:

- Redis restart drops correlation memory
- stored alerts remain durable in PostgreSQL, but no automatic replay into correlation state is implemented

## Enrichment Model

Current enrichments:

- GeoIP
- ASN
- asset role
- service criticality
- user identity
- static reputation score
- suppression and allowlist context

Sources:

- local YAML files in `backend/config`
- optional GeoIP mmdb files if present

Suppression behavior:

- suppression prevents alert creation
- suppression does not prevent event storage

This is intentional. Analysts still need the telemetry, even if the system chooses not to alert on it.

## Integrity Chain Behavior

Every stored entity becomes a chain record. The chain is linear and forward-linked by `prev_hash`.

Verification path:

1. recompute `contract_hash`
2. compare `prev_hash`
3. recompute entity payload hash from the database
4. compare with stored `payload_hash`

Trade-off:

- this catches post-write tampering inside the platform
- it does not prove the source host was trustworthy

## Retention

Retention job:

- `backend/retention.py`

Current behavior:

- delete events older than `SIEM_EVENT_RETENTION_DAYS`
- delete alerts older than `SIEM_ALERT_RETENTION_DAYS`
- delete ingest audit rows older than `SIEM_AUDIT_RETENTION_DAYS`

Important limitation:

- integrity-chain retention is not implemented because naive deletion breaks chain continuity

## Failure and Recovery Summary

### Redis stream unavailable

- ingest fails closed
- worker processing stops
- agent spool becomes the buffer

### Redis state unavailable

- rate limiting, replay protection, retries, detection state, and correlation state fail with Redis
- PostgreSQL durability is unchanged

### PostgreSQL unavailable

- workers do not acknowledge messages
- backlog accumulates in Redis until storage returns or queue retention becomes a problem

### Poison message

- retried deterministically
- dead-lettered after `N` attempts
- inspectable through the API

## Operational Limits

Where this design breaks first:

- long-lived high-volume event retention in PostgreSQL
- large rule packs with many regexes
- Redis single-instance outage affecting queueing and state together
- state loss after Redis restart

Why:

- PostgreSQL is doing both durable retention and recent operational query work
- the detection engine is still interpreted, not indexed
- Redis is still a single operational failure domain even though keyspaces are separated
