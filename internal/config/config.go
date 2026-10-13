// Package config loads and provides Tracker configuration.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version       string              `yaml:"version"`
	Server        ServerConfig        `yaml:"server"`
	NATS          NATSConfig          `yaml:"nats"`
	Storage       StorageConfig       `yaml:"storage"`
	Realtime      RealtimeConfig      `yaml:"realtime"`
	Alerting      AlertingConfig      `yaml:"alerting"`
	Demo          DemoConfig          `yaml:"demo"`
	Pipelines     PipelineConfig      `yaml:"pipelines"`
	Auth          AuthConfig          `yaml:"auth"`
	Logging       LoggingConfig       `yaml:"logging"`
	Metrics       MetricsConfig       `yaml:"metrics"`
	BypassMonitor BypassMonitorConfig `yaml:"bypass_monitor"`
	Monitor       MonitorConfig       `yaml:"monitor"`
	Anomaly       AnomalyConfig       `yaml:"anomaly"`
	// DevMode skips ValidateSecurity so the demo runs with built-in keys and
	// seed users. Never enable in production.
	DevMode bool `yaml:"dev_mode"`
}

// AnomalyConfig controls the statistical and pattern-based anomaly detector.
type AnomalyConfig struct {
	Enabled bool `yaml:"enabled"`
	// Statistical baseline: flag events > SigmaThreshold standard deviations above mean.
	SigmaThreshold float64 `yaml:"sigma_threshold"` // default 3.0
	WindowHours    int     `yaml:"window_hours"`    // rolling window for baseline; default 1
	// Pattern rules
	HighFreqUserLimit   int    `yaml:"high_freq_user_limit"`   // requests/minute; default 30
	RepeatedBlockWindow string `yaml:"repeated_block_window"`  // e.g. "5m"; default "5m"
	RepeatedBlockCount  int    `yaml:"repeated_block_count"`   // blocks in window; default 3
	// Active hours: outside these hours, access is flagged (24h clock, per-tenant override TBD)
	ActiveHoursStart int `yaml:"active_hours_start"` // 0–23; default 0 (disabled)
	ActiveHoursEnd   int `yaml:"active_hours_end"`   // 0–23; default 0 (disabled)
}

// MonitorConfig controls the pipeline monitoring / human-in-the-loop mode.
type MonitorConfig struct {
	// Mode is the initial monitoring mode: "off" (default), "observe", or "gate".
	// Can be changed at runtime via POST /v1/monitor/mode.
	Mode string `yaml:"mode"`
	// SessionRetentionHours is how long completed sessions are kept in memory (default 24).
	SessionRetentionHours int `yaml:"session_retention_hours"`
	// CheckpointTimeoutSec is how long a gate checkpoint waits for a human decision
	// before timing out (default 300 seconds = 5 minutes).
	CheckpointTimeoutSec int `yaml:"checkpoint_timeout_sec"`
	// AutoApproveOnTimeout: when true a timed-out checkpoint is treated as approved.
	// Default false (fail-safe: timeout = reject).
	AutoApproveOnTimeout bool `yaml:"auto_approve_on_timeout"`
}

// BypassMonitorConfig controls pipeline bypass anomaly detection.
type BypassMonitorConfig struct {
	Enabled         bool     `yaml:"enabled"`
	SensitiveLabels []string `yaml:"sensitive_labels"`
}

type ServerConfig struct {
	RESTPort      int `yaml:"rest_port"`
	GRPCPort      int `yaml:"grpc_port"`
	WebSocketPort int `yaml:"websocket_port"`
	UIPort        int `yaml:"ui_port"`
	// CORSAllowedOrigins lists browser origins allowed to call the REST API.
	// Empty (default) sends no CORS headers; "*" allows any origin.
	CORSAllowedOrigins []string `yaml:"cors_allowed_origins"`
	// TrustProxy honours X-Forwarded-For / X-Real-IP for the client address.
	// Enable only when Tracker sits behind a proxy that sets them.
	TrustProxy bool `yaml:"trust_proxy"`
}

type NATSConfig struct {
	URL        string   `yaml:"url"`
	Subjects   []string `yaml:"subjects"`
	MaxPending int      `yaml:"max_pending"`
}

type StorageConfig struct {
	PostgreSQLURL   string `yaml:"postgresql_url"`
	RetentionDays   int    `yaml:"retention_days"`
	MaxEventsMemory int    `yaml:"max_events_memory"`
	AuditSecret     string `yaml:"audit_secret"` // HMAC key for event signing (>=32 bytes; env TRACKER_AUDIT_SECRET); required unless dev_mode
}

type RealtimeConfig struct {
	MaxConnections    int    `yaml:"max_connections"`
	HeartbeatInterval string `yaml:"heartbeat_interval"`
	BufferSize        int    `yaml:"buffer_size"`
}

type AlertRule struct {
	Name             string   `yaml:"name"`
	Condition        string   `yaml:"condition"`
	Severity         string   `yaml:"severity"`
	Channels         []string `yaml:"channels"`          // slack, email, webhook
	EscalateAfter    string   `yaml:"escalate_after"`    // e.g. "15m"
	AutoResolveAfter string   `yaml:"auto_resolve_after"` // e.g. "1h"
}

// Condition format:
//   module.event_type   – exact match
//   *.event_type        – any module
//   module.*            – any event from module
//   severity:<level>    – any event at this severity (info/warning/error/critical)
//   status:<status>     – any event with this status (passed/blocked/error)
//   bare_event_type     – match event_type regardless of module

type AlertingConfig struct {
	Enabled bool         `yaml:"enabled"`
	Rules   []AlertRule  `yaml:"rules"`
	Slack   SlackConfig  `yaml:"slack"`
	Email   EmailConfig  `yaml:"email"`
	Webhook WebhookConfig `yaml:"webhook"`
}

type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type EmailConfig struct {
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
}

type WebhookConfig struct {
	URL string `yaml:"url"`
}

// AuthConfig controls JWT authentication for the REST API.
type AuthConfig struct {
	Enabled        bool         `yaml:"enabled"`
	JWTSecret      string       `yaml:"jwt_secret"`
	JWTExpiry      string       `yaml:"jwt_expiry"`      // e.g. "24h"
	RefreshExpiry  string       `yaml:"refresh_expiry"`  // e.g. "168h" (7 days); default = JWTExpiry
	RequireBcrypt  bool         `yaml:"require_bcrypt"`  // reject plaintext passwords when true
	Users          []UserConfig `yaml:"users"`
}

// UserConfig represents a single API user with a role.
// Password may be a plain-text string (PoC) or a bcrypt hash ($2a$...).
type UserConfig struct {
	Name     string `yaml:"name"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"` // admin, operator, viewer
}

type DemoConfig struct {
	Enabled       bool    `yaml:"enabled"`
	ScenariosPath string  `yaml:"scenarios_path"`
	DefaultSpeed  float64 `yaml:"default_speed"`
}

type PipelineConfig struct {
	Full    []string `yaml:"full"`
	Lite    []string `yaml:"lite"`
	Minimal []string `yaml:"minimal"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// Defaults returns a usable configuration for standalone/PoC mode.
func Defaults() *Config {
	return &Config{
		Version: "3.0",
		Server: ServerConfig{
			RESTPort:      8080,
			GRPCPort:      9090,
			WebSocketPort: 8081,
			UIPort:        3000,
		},
		NATS: NATSConfig{
			URL:        "nats://localhost:4222",
			Subjects:   []string{"bastion.events.>"},
			MaxPending: 100000,
		},
		Storage: StorageConfig{
			RetentionDays:   30,
			MaxEventsMemory: 10000,
		},
		Realtime: RealtimeConfig{
			MaxConnections:    1000,
			HeartbeatInterval: "30s",
			BufferSize:        1000,
		},
		Alerting: AlertingConfig{
			Enabled: true,
			Rules: []AlertRule{
				{Name: "honey_token_triggered", Condition: "security.honey_token_triggered", Severity: "critical"},
				{Name: "prompt_injection_detected", Condition: "sentinel.prompt_injection_detected", Severity: "warning"},
				{Name: "cross_tenant_attempt", Condition: "vault.cross_tenant_attempt", Severity: "warning"},
				{Name: "module_degraded", Condition: "system.module_degraded", Severity: "warning"},
				{Name: "any_critical_event", Condition: "severity:critical", Severity: "critical"},
			},
		},
		Demo: DemoConfig{
			Enabled:       true,
			ScenariosPath: "./scenarios",
			DefaultSpeed:  1.0,
		},
		Pipelines: PipelineConfig{
			Full:    []string{"sentinel", "vault", "navigator", "anchor", "llm"},
			Lite:    []string{"sentinel", "navigator", "anchor", "llm"},
			Minimal: []string{"sentinel", "navigator", "llm"},
		},
		Auth: AuthConfig{
			Enabled:       false, // off by default; enable in config.yaml
			JWTSecret:     "", // required when auth is enabled (>=32 bytes; env TRACKER_JWT_SECRET)
			JWTExpiry:     "8h",
			RefreshExpiry: "168h",
			RequireBcrypt: false, // flip to true in production
			Users: []UserConfig{
				{Name: "admin", Password: "admin", Role: "admin"},
				{Name: "ops", Password: "ops", Role: "operator"},
				{Name: "viewer", Password: "viewer", Role: "viewer"},
			},
		},
		Anomaly: AnomalyConfig{
			Enabled:             true,
			SigmaThreshold:      3.0,
			WindowHours:         1,
			HighFreqUserLimit:   30,
			RepeatedBlockWindow: "5m",
			RepeatedBlockCount:  3,
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		Metrics: MetricsConfig{Enabled: true, Port: 9091},
		BypassMonitor: BypassMonitorConfig{
			Enabled:         true,
			SensitiveLabels: []string{"pii", "sensitive", "confidential", "restricted"},
		},
		Monitor: MonitorConfig{
			Mode:                  "off",
			SessionRetentionHours: 24,
			CheckpointTimeoutSec:  300,
			AutoApproveOnTimeout:  false,
		},
	}
}

// Load reads a YAML config file, falling back to defaults for missing fields.
// TRACKER_AUDIT_SECRET and TRACKER_JWT_SECRET override the corresponding keys.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return cfg, err
		}
	}
	if v := os.Getenv("TRACKER_AUDIT_SECRET"); v != "" {
		cfg.Storage.AuditSecret = v
	}
	if v := os.Getenv("TRACKER_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	return cfg, nil
}

const minSecretLen = 32

// ValidateSecurity refuses insecure configurations: a missing or weak audit
// HMAC key (which would make the audit log forgeable), and, when auth is on,
// a missing/placeholder JWT secret or plaintext user passwords. dev_mode skips it.
func (c *Config) ValidateSecurity() error {
	if c.DevMode {
		return nil
	}
	if len(c.Storage.AuditSecret) < minSecretLen {
		return fmt.Errorf("storage.audit_secret must be set to at least %d bytes (env TRACKER_AUDIT_SECRET); without it audit signatures use a public key and are forgeable", minSecretLen)
	}
	if !c.Auth.Enabled {
		return nil
	}
	if s := c.Auth.JWTSecret; len(s) < minSecretLen || s == "change-me-in-production" {
		return fmt.Errorf("auth.jwt_secret must be a unique value of at least %d bytes (env TRACKER_JWT_SECRET)", minSecretLen)
	}
	for _, u := range c.Auth.Users {
		if !strings.HasPrefix(u.Password, "$2") {
			return fmt.Errorf("auth.users[%q]: password must be a bcrypt hash when auth is enabled", u.Name)
		}
	}
	return nil
}
