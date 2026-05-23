# Bastion-Tracker (Module D)

## Overview
**Bastion-Tracker** is the central observability and governance module for the Bastion framework. It provides real-time visualization of request flows, immutable audit logging, and honey-token intrusion detection.

Tracker acts as the "control center" for the entire RAG pipeline, allowing operators to monitor system health and security events across all modules.

## Key Features
- **Real-time Flow Visualization:** Live animation of requests moving through Bastion modules (Sentinel, Vault, Navigator, Anchor).
- **System Topology:** Graphical representation of module health and connectivity.
- **Audit Logging:** Secure, structured storage of all security-relevant events.
- **Honey-token Detection:** Management and monitoring of decoy data to detect unauthorized access.
- **Pipeline Variation Tracking:** Visualizing different pipeline paths (Full, Lite, Bypass) based on configuration.
- **Operations Dashboard:** Centralized view for SRE/Ops teams with metrics and incident alerts.

## Architecture
- **Event Collector:** Receives events from all modules via NATS or gRPC.
- **Trace Aggregator:** Correlates spans into end-to-end request traces.
- **Visualizer (Web UI):** React-based dashboard for real-time monitoring.
- **Storage Engine:** PostgreSQL for structured logs, Prometheus for metrics.

## Getting Started
### Prerequisites
- Go 1.21+
- Node.js & NPM (for Frontend)
- NATS Server
- PostgreSQL

### Installation
```bash
# Backend
go build -o tracker-server ./cmd/tracker
# Frontend
cd ui && npm install && npm run build
```

## Documentation
- [Design Document](DESIGN.md)
- [SRS Document](bastion_tracker_srs_v1.0_en.md)

## License
Apache License 2.0
