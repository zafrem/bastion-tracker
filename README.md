# Bastion-Tracker (Module D)

## Overview
**Bastion-Tracker** is the central observability and governance module for the Bastion-RAG framework. It provides real-time visualization of request flows, immutable audit logging, and honey-token intrusion detection.

Tracker acts as the "control center" for the entire RAG pipeline, allowing operators to monitor system health and security events across all modules (Sentinel, Vault, Navigator, Anchor).

## Key Features
- **Real-time Flow Visualization:** Live streaming of requests moving through the Bastion-RAG modules via WebSocket.
- **System Topology:** Module health and connectivity derived from recent event windows.
- **Audit Logging:** Structured storage of all security-relevant events with configurable retention.
- **Data Lineage Tracking:** Trace how data flows through the pipeline, queryable by `trace_id`, `user_id`, or audit scope.
- **Honey-token Detection:** Monitoring of decoy data; access triggers high-severity alerts.
- **Pipeline Variation Tracking:** Visualizes different pipeline paths (Full, Lite, Minimal) based on configuration.
- **Alerting & Incidents:** Rule-based alerts (honey-token, prompt injection, cross-tenant, module degradation) with incident management.
- **Operations Dashboard:** Centralized view for SRE/Ops teams with metrics and incident alerts.

## Architecture
- **Event Collector:** Receives events from all modules via NATS (primary) or gRPC/REST (fallback).
- **Trace Aggregator:** Correlates spans into end-to-end request traces.
- **WebSocket Hub:** Pushes live events to connected clients for real-time monitoring.
- **Storage Engine:** In-memory ring buffer for PoC; PostgreSQL is the production target.
- **Metrics:** Prometheus-compatible metrics endpoint.
- **Web UI ("Control Center"):** A single self-contained `index.html` (Vanilla JS/CSS/SVG, zero dependencies) embedded into the Go binary via `go:embed` and served directly by the REST server — no separate Node/React build step.

```
  [Bastion-RAG Modules (A, B, C, E)]
             |
             v  (NATS / gRPC / REST)
      [Event Collector]
             |
      [Trace Aggregator] ----> [In-memory Ring Buffer / PostgreSQL*]
             |
      [WebSocket Hub]    ----> [Prometheus / Metrics]
             |
             v
      [Web UI (Vanilla JS / React*)]
```
*\* PostgreSQL and React are production targets; the PoC uses an in-memory store and a zero-dependency Vanilla JS UI.*

## Getting Started
### Prerequisites
- Go 1.21+
- NATS Server (optional; gRPC/REST fallback available)

### Build
```bash
# Build the CLI/server binary to bin/tracker-cli
make build
# or directly:
go build -o bin/tracker-cli ./cmd/tracker-cli
```

### Run
```bash
make run            # start the REST + gRPC + WebSocket server
make demo           # start the server and run all demo scenarios
make stream         # tail live events from the WebSocket
make generate       # generate synthetic event traffic
```

### CLI Commands
The `tracker-cli` binary exposes the following commands:

| Command | Description |
|---------|-------------|
| `server` | Start the Tracker REST + gRPC server |
| `demo-server` | Start the server and immediately run all demo scenarios |
| `stream` | Stream live events from the Tracker WebSocket |
| `traces` | List recent request traces |
| `trace <trace_id>` | Show detail for a single trace |
| `lineage <trace_id\|user:<user_id>\|audit>` | Query data lineage (SRS doc 22) |
| `security incidents` | List open incidents |
| `security alerts` | List firing alerts |
| `demo list` | List available demo scenarios |
| `demo replay <scenario-name>` | Replay a demo scenario |
| `inject` | Inject a synthetic event |
| `generate` | Generate synthetic event traffic |

### Configuration
Default ports (see [`config/config.yaml`](config/config.yaml)):

| Service | Port |
|---------|------|
| REST API + Web UI | 8080 |
| gRPC | 9090 |
| WebSocket | 8081 |
| Metrics (Prometheus) | 9091 |

The embedded dashboard is served by the REST server at http://localhost:8080/.
(`config.yaml` also defines `ui_port: 3000`, but it is currently unused — the UI
runs on `server.rest_port`.)

Storage defaults to in-memory (PoC mode); set `storage.postgresql_url` to enable PostgreSQL.

## Documentation
- [Design Document](DESIGN.md)
- [SRS Document (v3)](docs/14_module_tracker_srs_v3.md)

**Technical deep-dives (code-based):**
- [Lineage Tracking](docs/lineage-tracking.md)
- [Honey-Token Injection](docs/honey-token-injection.md)
- [Management Features](docs/management-features.md)

## License
Apache License 2.0
