# Bastion-Tracker Design Document

## 1. Introduction
Tracker is Module D of the Bastion-RAG framework, providing comprehensive observability and audit capabilities. It ensures transparency and accountability by tracking every request through the RAG pipeline.

## 2. System Architecture

### 2.1 Component Overview
```
  [Bastion-RAG Modules (A,B,C,E)]
             |
             v (NATS / gRPC / REST)
      [Event Collector]
             |
      [Trace Aggregator] ----> [In-memory Ring Buffer / PostgreSQL*]
             |
      [WebSocket Hub]    ----> [Prometheus / Metrics]
             |
             v
      [Web UI (Vanilla JS / React*)]
```
*\* PostgreSQL and React are targets for production; PoC uses In-memory store and Vanilla JS.*

### 2.2 Event Schema
Tracker uses a standardized event schema across all modules:
- `trace_id`: Unique identifier for the request.
- `span_id`: Identifier for the specific operation.
- `module`: Originating module (sentinel, vault, etc.).
- `event_type`: Nature of the event (e.g., `pii_detected`, `search_completed`).
- `severity`: info, warning, error, critical.
- `payload`: Context-specific data in JSON format.

## 3. Real-time Visualization
The core value of Tracker is its live visualization:
- **Request Animation:** Uses WebSockets to push events to the UI, showing the path of a request through the module graph in real-time.
- **Health Indicators:** Modules change color based on their liveness and error rates, computed from recent event windows.
- **Pipeline Highlighting:** Different routes (e.g., bypassing Vault for public data) are visually distinct via animated SVG paths.

## 4. Audit & Compliance
- **Immutability:** Audit logs are stored in a write-optimized database with strict retention policies (PoC uses in-memory ring buffer).
- **Searchability:** Operators can query traces by `user_id`, `tenant_id`, or specific security incidents.
- **Reports:** Generates daily/weekly security compliance summaries.

## 5. Honey-token System
- **Injection:** Works with Navigator to inject decoy documents into search results.
- **Detection:** If a honey-token is accessed or used in a query, Tracker triggers a high-severity alert.

## 6. Technical Stack
- **Backend:** Go 1.21+
- **Frontend (PoC):** Vanilla HTML5/JS, CSS3, SVG (Zero-dependency)
- **Frontend (Target):** React, TailwindCSS, D3.js
- **Messaging:** NATS (Primary), gRPC/REST (Fallback)
- **Database (PoC):** In-memory Ring Buffer
- **Database (Target):** PostgreSQL (Events), Loki (Logs), Jaeger (Traces)
- **Metrics:** Prometheus
