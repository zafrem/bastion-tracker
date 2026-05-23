// Package config loads and provides Tracker configuration.
package config

import (
	"os"

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
	AuditSecret     string `yaml:"audit_secret"` // HMAC key for event signing; uses built-in demo key if empty
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
	Enabled   bool         `yaml:"enabled"`
	JWTSecret string       `yaml:"jwt_secret"`
	JWTExpiry string       `yaml:"jwt_expiry"` // e.g. "24h"
	Users     []UserConfig `yaml:"users"`
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
		Version: "1.0",
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
			Enabled:   false, // off by default; enable in config.yaml
			JWTSecret: "change-me-in-production",
			JWTExpiry: "24h",
			Users: []UserConfig{
				{Name: "admin", Password: "admin", Role: "admin"},
				{Name: "ops", Password: "ops", Role: "operator"},
				{Name: "viewer", Password: "viewer", Role: "viewer"},
			},
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		Metrics: MetricsConfig{Enabled: true, Port: 9091},
		BypassMonitor: BypassMonitorConfig{
			Enabled:         true,
			SensitiveLabels: []string{"pii", "sensitive", "confidential", "restricted"},
		},
	}
}

// Load reads a YAML config file, falling back to defaults for missing fields.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil
	}
	return cfg, yaml.Unmarshal(data, cfg)
}
