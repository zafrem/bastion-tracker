// Package demo provides pre-built PoC demonstration scenarios.
package demo

import (
	"fmt"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// BuiltinScenarios returns all pre-defined demo event sequences.
func BuiltinScenarios() []models.DemoScenario {
	return []models.DemoScenario{
		normalFlow(),
		promptInjection(),
		piiAnonymization(),
		crossTenantPrevention(),
		honeyTokenDetection(),
		moduleBypass(),
		anchorDegraded(),
		incidentResponse(),
	}
}

var epoch = time.Date(2026, 5, 17, 14, 23, 45, 0, time.UTC)

func ts(offset int64) time.Time {
	return epoch.Add(time.Duration(offset) * time.Millisecond)
}

// ev is a shorthand DemoEvent constructor.
func ev(offset int64, module, eventType, severity, status, pipeline, tenantID, userID, requestID string, durationMs int64, data map[string]any) models.DemoEvent {
	return models.DemoEvent{
		OffsetMs: offset,
		Event: models.BastionEvent{
			EventID:      fmt.Sprintf("%s-%s-%d", module, eventType, offset),
			TraceID:      "trace-" + requestID,
			SpanID:       fmt.Sprintf("%s-%d", module, offset),
			Module:       module,
			EventType:    eventType,
			Severity:     severity,
			Timestamp:    ts(offset),
			TenantID:     tenantID,
			UserID:       userID,
			RequestID:    requestID,
			PipelineType: pipeline,
			DurationMs:   durationMs,
			Status:       status,
			Data:         data,
		},
	}
}

func normalFlow() models.DemoScenario {
	rID := "req-12345"
	return models.DemoScenario{
		Name:        "01-normal-flow",
		Description: "Normal request through the full pipeline (A→B→C→E→LLM)",
		DurationSec: 30,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 0, nil),
			ev(10, "sentinel", "validation_passed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 8, map[string]any{"injection_score": 0.12}),
			ev(20, "vault", "request_received", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 0, nil),
			ev(30, "vault", "anonymization_applied", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 42, map[string]any{"pii_fields_masked": 3}),
			ev(80, "navigator", "search_started", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 0, nil),
			ev(160, "navigator", "search_completed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 78, map[string]any{"results": 10, "strategy": "hybrid"}),
			ev(170, "anchor", "embedding_secured", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 35, map[string]any{"noise_injected": true}),
			ev(1500, "llm", "response_generated", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 1320, map[string]any{"tokens_in": 1234, "tokens_out": 567}),
		},
	}
}

func promptInjection() models.DemoScenario {
	rID := "req-12346"
	return models.DemoScenario{
		Name:        "02-prompt-injection",
		Description: "Sentinel blocks a prompt injection attempt",
		DurationSec: 20,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "warning", "passed", "full", "tenant-acme", "xyz@acme", rID, 0, nil),
			ev(50, "sentinel", "prompt_injection_detected", "critical", "blocked", "full", "tenant-acme", "xyz@acme", rID, 12, map[string]any{"pattern": "ignore all previous instructions", "score": 0.97}),
			ev(55, "sentinel", "validation_blocked", "critical", "blocked", "full", "tenant-acme", "xyz@acme", rID, 0, map[string]any{"reason": "prompt_injection"}),
		},
		Annotations: []models.Annotation{
			{OffsetMs: 40, Text: "Suspicious request arrives — injection score 0.97", Style: "warning"},
			{OffsetMs: 52, Text: "Sentinel blocks the request before it reaches LLM", Style: "critical"},
		},
	}
}

func piiAnonymization() models.DemoScenario {
	rID := "req-12347"
	return models.DemoScenario{
		Name:        "03-pii-anonymization",
		Description: "Vault detects and masks PII in a customer data query",
		DurationSec: 40,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 0, nil),
			ev(8, "sentinel", "validation_passed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 8, nil),
			ev(20, "vault", "pii_detected", "warning", "passed", "full", "tenant-acme", "alice@acme", rID, 0, map[string]any{"fields": []string{"email", "phone", "ssn"}}),
			ev(65, "vault", "anonymization_applied", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 45, map[string]any{"fields_masked": 3, "k_anonymity": 5}),
			ev(140, "navigator", "search_completed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 75, nil),
			ev(150, "anchor", "embedding_secured", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 10, nil),
		},
	}
}

func crossTenantPrevention() models.DemoScenario {
	rID := "req-12348"
	return models.DemoScenario{
		Name:        "04-cross-tenant",
		Description: "Vault blocks a cross-tenant data access attempt",
		DurationSec: 25,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "info", "passed", "full", "tenant-globex", "bob@globex", rID, 0, nil),
			ev(8, "sentinel", "validation_passed", "info", "passed", "full", "tenant-globex", "bob@globex", rID, 8, nil),
			ev(20, "vault", "cross_tenant_attempt", "critical", "blocked", "full", "tenant-globex", "bob@globex", rID, 5, map[string]any{"target_tenant": "tenant-acme", "resource": "customer_data"}),
			ev(25, "vault", "access_denied", "critical", "blocked", "full", "tenant-globex", "bob@globex", rID, 0, map[string]any{"reason": "cross_tenant_violation"}),
		},
	}
}

func honeyTokenDetection() models.DemoScenario {
	rID := "req-12349"
	return models.DemoScenario{
		Name:        "05-honey-token",
		Description: "Attacker accesses a honey-token, triggering an incident",
		DurationSec: 35,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "info", "passed", "full", "tenant-acme", "attacker@external", rID, 0, nil),
			ev(10, "sentinel", "validation_passed", "info", "passed", "full", "tenant-acme", "attacker@external", rID, 10, nil),
			ev(80, "navigator", "search_completed", "info", "passed", "full", "tenant-acme", "attacker@external", rID, 50, nil),
			ev(500, "security", "honey_token_triggered", "critical", "error", "full", "tenant-acme", "attacker@external", rID, 0, map[string]any{"token_id": "HT-0001", "token_name": "Fake CEO Email", "source_ip": "192.168.1.123"}),
		},
		Annotations: []models.Annotation{
			{OffsetMs: 75, Text: "Attacker retrieves search results containing decoy data", Style: "warning"},
			{OffsetMs: 490, Text: "Honey-token 'Fake CEO Email' accessed — incident auto-created", Style: "critical"},
		},
	}
}

func moduleBypass() models.DemoScenario {
	rID := "req-12350"
	return models.DemoScenario{
		Name:        "06-module-bypass",
		Description: "Public document query uses lite pipeline (Vault skipped)",
		DurationSec: 25,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "request_received", "info", "passed", "lite", "tenant-public", "anon@public", rID, 0, nil),
			ev(5, "sentinel", "pipeline_routing_decided", "info", "passed", "lite", "tenant-public", "anon@public", rID, 0, map[string]any{"pipeline_type": "lite", "modules_skipped": []string{"vault"}, "reason": "public_data_category"}),
			ev(10, "sentinel", "validation_passed", "info", "passed", "lite", "tenant-public", "anon@public", rID, 10, nil),
			ev(80, "navigator", "search_completed", "info", "passed", "lite", "tenant-public", "anon@public", rID, 70, map[string]any{"results": 5}),
			ev(90, "anchor", "embedding_secured", "info", "passed", "lite", "tenant-public", "anon@public", rID, 10, nil),
		},
	}
}

func anchorDegraded() models.DemoScenario {
	rID := "req-12351"
	return models.DemoScenario{
		Name:        "07-anchor-degraded",
		Description: "Anchor module shows elevated latency (degraded state)",
		DurationSec: 30,
		Events: []models.DemoEvent{
			ev(0, "sentinel", "validation_passed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 8, nil),
			ev(50, "vault", "anonymization_applied", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 42, nil),
			ev(130, "navigator", "search_completed", "info", "passed", "full", "tenant-acme", "alice@acme", rID, 78, nil),
			ev(340, "anchor", "embedding_secured", "warning", "passed", "full", "tenant-acme", "alice@acme", rID, 210, map[string]any{"latency_spike": true}),
			ev(345, "system", "module_degraded", "warning", "error", "full", "tenant-acme", "", rID, 0, map[string]any{"module": "anchor", "reason": "latency_p95_exceeded"}),
		},
	}
}

func incidentResponse() models.DemoScenario {
	rID := "req-12352"
	return models.DemoScenario{
		Name:        "08-incident-response",
		Description: "Full incident workflow: detection → escalation → resolution",
		DurationSec: 60,
		Events: []models.DemoEvent{
			ev(0, "security", "honey_token_triggered", "critical", "error", "full", "tenant-acme", "suspect@external", rID, 0, map[string]any{"token_id": "HT-0001"}),
			ev(100, "security", "suspicious_pattern", "critical", "error", "full", "tenant-acme", "suspect@external", rID, 0, map[string]any{"attempts": 5}),
			ev(500, "security", "anomaly_detected", "critical", "error", "full", "tenant-acme", "suspect@external", rID, 0, map[string]any{"anomaly": "bulk_data_access"}),
			ev(1000, "security", "incident_created", "critical", "error", "full", "tenant-acme", "", "INC-0001", 0, map[string]any{"incident_id": "INC-0001", "title": "Possible data exfiltration"}),
		},
		Annotations: []models.Annotation{
			{OffsetMs: 0, Text: "Honey-token triggered — possible attacker foothold", Style: "critical"},
			{OffsetMs: 90, Text: "Pattern of suspicious access detected (5 attempts)", Style: "warning"},
			{OffsetMs: 490, Text: "Bulk data access anomaly detected", Style: "critical"},
			{OffsetMs: 990, Text: "Incident INC-0001 created — investigation begins", Style: "info"},
		},
	}
}
