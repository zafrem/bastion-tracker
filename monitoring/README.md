# Monitoring Tracker

Metrics, alert rules, alert routing and a Grafana dashboard for Bastion-Tracker.

## Start the stack

```bash
export TRACKER_AUDIT_SECRET=$(openssl rand -hex 32)
export GRAFANA_ADMIN_PASSWORD=...          # without it Grafana starts with admin/admin
docker compose --profile monitoring up -d --build
python3 monitoring/check_stack.py          # verifies scraping, rules, alert path and dashboard
```

| What | Address |
|---|---|
| Grafana dashboard "Bastion Tracker" (folder Bastion) | http://localhost:3001 |
| Prometheus | http://localhost:9092 |
| Alertmanager | http://localhost:9093 |
| Tracker metrics | http://localhost:9091/metrics |

All four are published on localhost only. Prometheus, Alertmanager and the metrics port have **no
authentication**; if you expose them, put them behind a proxy that has it.

## Before relying on it

1. **Deliver the alerts.** As shipped, Alertmanager shows alerts but sends them nowhere. Add an integration to the
   `operators` receiver in [`alertmanager/alertmanager.yml`](alertmanager/alertmanager.yml).
2. **Watch the monitoring.** `Watchdog` always fires. Send it (receiver `deadman`) to a service that pages when it
   stops arriving; that is the only way to learn that Prometheus or Alertmanager has died.
3. **Tune thresholds** in [`prometheus/rules/tracker.yml`](prometheus/rules/tracker.yml), the memory limit first.

## Health endpoints (REST port)

| Endpoint | Meaning |
|---|---|
| `/v1/health/live` | The process answers. Use for liveness. |
| `/v1/health/ready` | The API can serve. It deliberately ignores NATS: REST and gRPC ingestion still work without it. |
| `/v1/health` | `status` is `ok`, or `degraded` while a NATS connection is down; `checks` says which. Always HTTP 200. |

## Metrics

`tracker.metrics` in `config/config.yaml`: `enabled` and `port` control the dedicated listener (startup fails if
the port is taken); `expose_on_rest` also serves `/v1/metrics` on the public REST port.

| Area | Metrics (prefix `tracker_`) |
|---|---|
| Events | `events_received_total`, `events_processed_total`, `events_rejected_total`, `event_processing_duration_seconds`, `last_event_timestamp_seconds`, `pipeline_requests_total` |
| NATS | `nats_connected`, `nats_reconnects_total`, `nats_messages_received_total`, `nats_messages_dropped_total`, `nats_pending_messages`, `nats_decode_errors_total`, `events_published_total` |
| APIs | `http_requests_total`, `http_request_duration_seconds`, `http_requests_in_flight`, `grpc_requests_total`, `grpc_request_duration_seconds`, `panics_total` |
| Security | `alerts_fired_total`, `alerts`, `active_alerts`, `incidents`, `incidents_created_total`, `honey_token_triggers_total`, `anomalies_total`, `logins_total` |
| Delivery | `notifications_total`, `websocket_connections`, `websocket_broadcasts_total`, `broadcast_dropped_total` |
| State | `store_events`, `store_event_capacity`, `store_events_written_total`, `store_traces`, `store_lineage_traces`, `monitor_sessions`, `monitor_pending_checkpoints`, `monitor_oldest_pending_checkpoint_seconds`, `build_info` |

Standard `go_*` and `process_*` metrics are included (`process_*` on Linux).

**Label limits.** Module, event type and pipeline type come from whoever sends the event, so each accepts a
limited number of distinct values (24, 200 and 12); anything beyond that, or malformed, is counted as `other`.

## What this does not cover

- **State is in memory.** A restart empties events, traces, alerts and incidents, and resets counters.
- **Traces and lineage are never expired**, so memory grows with traffic. `TrackerTracesAccumulating` and
  `TrackerMemoryHigh` warn about it; they do not fix it.
- **Events sent while NATS or Tracker is down are lost** (core NATS does not keep them).
- **NATS server and host metrics** need their own exporters (for example `prometheus-nats-exporter`).
- **Logs** are plain text on stdout; collection and search are not set up here.
