// Package runbook provides pre-defined operational playbooks for common
// alert and incident types. Runbooks work fully offline with no external
// dependencies, so they are available in standalone/demo mode.
package runbook

// Step is one action in a runbook.
type Step struct {
	Order       int    `json:"order"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`           // check | command | notify | containment | escalate
	Command     string `json:"command,omitempty"` // example CLI/API call
	Automated   bool   `json:"automated"`
}

// RunBook is a playbook for responding to a specific alert or incident type.
type RunBook struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Category         string `json:"category"`          // security | operations | reliability
	Severity         string `json:"severity"`          // minimum triggering severity
	Triggers         []string `json:"triggers"`         // alert rule names this applies to
	Steps            []Step `json:"steps"`
	EstimatedMinutes int    `json:"estimated_minutes"`
}

// Manager holds all runbooks.
type Manager struct {
	books []RunBook
}

// New creates a Manager pre-loaded with default runbooks.
func New() *Manager {
	m := &Manager{}
	m.seed()
	return m
}

// List returns all runbooks.
func (m *Manager) List() []RunBook { return m.books }

// Get returns a runbook by ID.
func (m *Manager) Get(id string) (*RunBook, bool) {
	for i := range m.books {
		if m.books[i].ID == id {
			return &m.books[i], true
		}
	}
	return nil, false
}

// ForAlert returns runbooks whose Triggers list includes ruleName.
func (m *Manager) ForAlert(ruleName string) []RunBook {
	var out []RunBook
	for _, rb := range m.books {
		for _, t := range rb.Triggers {
			if t == ruleName || t == "*" {
				out = append(out, rb)
				break
			}
		}
	}
	return out
}

func (m *Manager) seed() {
	m.books = []RunBook{
		{
			ID:               "rb-prompt-injection",
			Name:             "Prompt Injection Response",
			Description:      "Containment and investigation steps for a detected prompt injection attack against the Sentinel module.",
			Category:         "security",
			Severity:         "warning",
			Triggers:         []string{"prompt_injection_detected"},
			EstimatedMinutes: 15,
			Steps: []Step{
				{Order: 1, Title: "Confirm detection", Action: "check",
					Description: "Open the Audit Log and filter by module=sentinel, event_type=prompt_injection_detected. Verify the payload excerpt — rule out test traffic and false positives."},
				{Order: 2, Title: "Identify affected tenant", Action: "check",
					Description: "Note the tenant_id and user_id. Search events from the past 24 h for this user to spot repeated attempts.",
					Command:     "GET /v1/events/search?q=prompt_injection&module=sentinel"},
				{Order: 3, Title: "Confirm Sentinel blocked it", Action: "check",
					Description: "The event status should be 'blocked'. If it is 'passed', treat as a successful injection — escalate immediately."},
				{Order: 4, Title: "Open an incident", Action: "containment",
					Description: "If the system did not auto-create an incident, open one manually on the Security page and link the event_id."},
				{Order: 5, Title: "Notify security team", Action: "notify",
					Description: "Send the incident_id, tenant_id, and injected payload excerpt to the security Slack channel."},
				{Order: 6, Title: "Harden and document", Action: "escalate",
					Description: "Add the attack pattern to Sentinel's detection corpus. Record findings in the incident notes and close the incident."},
			},
		},
		{
			ID:               "rb-honey-token",
			Name:             "Honey Token Triggered",
			Description:      "Forensic investigation procedure when a canary resource is accessed, indicating potential insider threat or credential compromise.",
			Category:         "security",
			Severity:         "critical",
			Triggers:         []string{"honey_token_triggered"},
			EstimatedMinutes: 30,
			Steps: []Step{
				{Order: 1, Title: "Identify the token", Action: "check",
					Description: "Navigate to Honey Tokens, find the triggered token, and note its type and location. This reveals what data the attacker was after."},
				{Order: 2, Title: "Collect trigger metadata", Action: "check",
					Description: "Open the Triggers list for that token. Record source IP, user_id, and tenant_id for every trigger.",
					Command:     "GET /v1/honey-tokens/{id}/triggers"},
				{Order: 3, Title: "Trace lateral movement", Action: "check",
					Description: "In the Audit Log, search events for the same user/IP in the ±30 min window around the trigger. Look for other accessed resources."},
				{Order: 4, Title: "Contain the account", Action: "containment",
					Description: "Revoke all active sessions for the implicated user. Coordinate with IAM to disable the account until investigation is complete."},
				{Order: 5, Title: "Preserve evidence", Action: "containment",
					Description: "Export all relevant event IDs from the Audit Log before the ring buffer overwrites them. Record them in the incident notes."},
				{Order: 6, Title: "Escalate to CISO", Action: "escalate",
					Description: "Honey-token access implies insider threat or credential compromise. Escalate to CISO immediately with a written summary."},
			},
		},
		{
			ID:               "rb-cross-tenant",
			Name:             "Cross-Tenant Access Attempt",
			Description:      "Steps to respond to data isolation violations detected by the Vault module.",
			Category:         "security",
			Severity:         "warning",
			Triggers:         []string{"cross_tenant_attempt"},
			EstimatedMinutes: 20,
			Steps: []Step{
				{Order: 1, Title: "Identify requester and target", Action: "check",
					Description: "Note the source tenant_id and user_id, and the target tenant they attempted to access."},
				{Order: 2, Title: "Verify Vault blocked it", Action: "check",
					Description: "If the event status is 'blocked', data isolation held. If 'passed', treat as a data breach and escalate immediately."},
				{Order: 3, Title: "Check for repeated probing", Action: "check",
					Description: "Search events for the same user in the past 1 h. Repeated attempts indicate deliberate enumeration.",
					Command:     "GET /v1/events?module=vault&user_id={user}&since=1h"},
				{Order: 4, Title: "Invalidate user session", Action: "containment",
					Description: "Force-expire the user's session tokens to stop any ongoing probing."},
				{Order: 5, Title: "Audit Vault isolation rules", Action: "check",
					Description: "Verify the tenant isolation configuration in the Vault module is correct for both the source and target tenants."},
				{Order: 6, Title: "Notify affected tenant (if breach)", Action: "notify",
					Description: "If the access was not blocked, notify the target tenant per your breach disclosure SLA timeline."},
			},
		},
		{
			ID:               "rb-bypass-anomaly",
			Name:             "Pipeline Bypass Anomaly",
			Description:      "Investigate unexpected pipeline routing detected for sensitive or high-risk data.",
			Category:         "security",
			Severity:         "warning",
			Triggers:         []string{"bypass_anomaly_detected", "any_critical_event"},
			EstimatedMinutes: 10,
			Steps: []Step{
				{Order: 1, Title: "Review the anomaly event", Action: "check",
					Description: "Open Security Events and find the bypass_anomaly_detected event. Note the anomaly_type field: 'sensitive_label_bypass' or 'pipeline_downgrade'."},
				{Order: 2, Title: "Assess the risk", Action: "check",
					Description: "If sensitive_label_bypass: PII data traversed lite/minimal pipeline, skipping Vault. If pipeline_downgrade: a tenant abruptly switched from full to lite without explanation."},
				{Order: 3, Title: "Review pipeline routing config", Action: "check",
					Description: "Verify the Navigator module's routing rules have not been misconfigured or tampered with."},
				{Order: 4, Title: "Determine if intentional", Action: "notify",
					Description: "Contact the team that owns the tenant. Was this an authorized pipeline change, an A/B experiment, or a bug?"},
				{Order: 5, Title: "Remediate", Action: "containment",
					Description: "If unintentional: revert the Navigator routing config. If intentional: update the bypass monitor's sensitive_labels allowlist to prevent future false alerts."},
			},
		},
		{
			ID:               "rb-module-degraded",
			Name:             "Module Health Degraded",
			Description:      "Triage and recovery runbook for a degraded or down pipeline module.",
			Category:         "operations",
			Severity:         "warning",
			Triggers:         []string{"module_degraded"},
			EstimatedMinutes: 20,
			Steps: []Step{
				{Order: 1, Title: "Identify the degraded module", Action: "check",
					Description: "Check the Dashboard topology view. Note which module is degraded and its current error rate and latency."},
				{Order: 2, Title: "Review recent errors", Action: "check",
					Description: "Filter the Audit Log by that module and status=error in the last 5 minutes to understand the failure pattern.",
					Command:     "GET /v1/events?module={module}&status=error&since=5m"},
				{Order: 3, Title: "Check system resources", Action: "command",
					Description: "On the host running the module, check CPU, memory, and network saturation.",
					Command:     "docker stats {module-container}"},
				{Order: 4, Title: "Check recent deployments", Action: "check",
					Description: "Was anything deployed in the last 30 minutes? Check deployment logs and git history."},
				{Order: 5, Title: "Restart module (if no root cause found)", Action: "command",
					Description: "If the issue persists without a clear root cause, restart the module container.",
					Command:     "docker compose restart {module}"},
				{Order: 6, Title: "Confirm recovery", Action: "check",
					Description: "Wait 60 seconds. Verify the topology view shows the module back to 'healthy'. Check error rate has returned to baseline."},
			},
		},
		{
			ID:               "rb-high-error-rate",
			Name:             "High Error Rate Triage",
			Description:      "General triage for any module showing elevated error rates or critical events.",
			Category:         "reliability",
			Severity:         "error",
			Triggers:         []string{"any_critical_event", "*"},
			EstimatedMinutes: 10,
			Steps: []Step{
				{Order: 1, Title: "Gauge the blast radius", Action: "check",
					Description: "Check the Pipeline Distribution chart on the Dashboard. Is the error rate affecting one tenant or all tenants?"},
				{Order: 2, Title: "Isolate the module", Action: "check",
					Description: "Filter events by each module to find which one is the source. Use the Audit Log with status=error."},
				{Order: 3, Title: "Check downstream impact", Action: "check",
					Description: "High error rate in Sentinel means blocked requests. In Vault it means isolation failures. Understand the user-visible impact."},
				{Order: 4, Title: "Alert on-call", Action: "notify",
					Description: "If impact is user-visible, page the on-call engineer with the affected module, tenant count, and error rate."},
				{Order: 5, Title: "Apply circuit breaker (if available)", Action: "containment",
					Description: "If the module supports it, enable circuit-breaker mode to fail-safe requests while the issue is resolved."},
			},
		},
	}
}
