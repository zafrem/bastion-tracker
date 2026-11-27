package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/metrics"
)

const monitoringDir = "../../monitoring/"

// exported lists every metric name Tracker serves, after giving each labelled metric one series.
func exported(t *testing.T) map[string]bool {
	t.Helper()
	metrics.EventsReceived.WithLabelValues("m", "e")
	metrics.EventsProcessed.WithLabelValues("m")
	metrics.ProcessingDuration.WithLabelValues("m")
	metrics.PipelineRequests.WithLabelValues("full", "passed")
	metrics.AlertsFired.WithLabelValues("r", "warning")
	metrics.Notifications.WithLabelValues("c", "success")
	metrics.Anomalies.WithLabelValues("p", "warning")
	metrics.HTTPRequests.WithLabelValues("GET", "/", "200")
	metrics.HTTPDuration.WithLabelValues("GET", "/")
	metrics.GRPCRequests.WithLabelValues("m", "OK")
	metrics.GRPCDuration.WithLabelValues("m")

	w := httptest.NewRecorder()
	metrics.Handler(metrics.Sources{
		Store: func() metrics.StoreStats {
			return metrics.StoreStats{Incidents: map[string]int{"open": 0}, Alerts: map[[2]string]int{{"firing", "info"}: 0}}
		},
		Monitor: func() metrics.MonitorStats { return metrics.MonitorStats{} },
		NATS:    []func() metrics.NATSStats{func() metrics.NATSStats { return metrics.NATSStats{Client: "collector"} }},
	}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(w.Body)

	names := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^(tracker_[a-z0-9_]+)`).FindAllStringSubmatch(string(body), -1) {
		names[m[1]] = true
	}
	return names
}

// A misspelt metric in an alert or panel does not fail: the alert just never fires and the panel stays empty.
func TestMonitoringConfig_UsesOnlyMetricsTrackerExports(t *testing.T) {
	names := exported(t)
	used := regexp.MustCompile(`\btracker_[a-z0-9_]+`)

	var queries []string
	var rules struct {
		Groups []struct {
			Rules []struct {
				Alert  string            `yaml:"alert"`
				Expr   string            `yaml:"expr"`
				Labels map[string]string `yaml:"labels"`
				Ann    map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	readYAML(t, monitoringDir+"prometheus/rules/tracker.yml", &rules)
	alerts := map[string]bool{}
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" || r.Expr == "" || r.Labels["severity"] == "" || r.Ann["summary"] == "" || r.Ann["description"] == "" {
				t.Errorf("incomplete alert rule: %+v", r)
			}
			if alerts[r.Alert] {
				t.Errorf("duplicate alert %s", r.Alert)
			}
			alerts[r.Alert] = true
			queries = append(queries, r.Expr)
		}
	}
	for _, want := range []string{"TrackerDown", "TrackerNATSDisconnected", "TrackerPanics", "TrackerHoneyTokenTriggered", "Watchdog"} {
		if !alerts[want] {
			t.Errorf("no %s alert", want)
		}
	}

	raw, err := os.ReadFile(monitoringDir + "grafana/dashboards/tracker.json")
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Type    string `json:"type"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatal(err)
	}
	for _, p := range dash.Panels {
		if p.Type != "row" && len(p.Targets) == 0 {
			t.Errorf("panel %q has no query", p.Title)
		}
		for _, q := range p.Targets {
			queries = append(queries, q.Expr)
		}
	}

	if len(queries) < 40 {
		t.Fatalf("found only %d queries to check", len(queries))
	}
	for _, q := range queries {
		for _, name := range used.FindAllString(q, -1) {
			if !names[name] {
				t.Errorf("query uses %s, which Tracker does not export: %s", name, q)
			}
		}
		if strings.Count(q, "(") != strings.Count(q, ")") || strings.Count(q, "{") != strings.Count(q, "}") {
			t.Errorf("unbalanced query: %s", q)
		}
	}
}

func TestMonitoringConfig_ScrapesTheConfiguredMetricsPort(t *testing.T) {
	cfg, err := config.Load("../../config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Metrics.Enabled || cfg.Metrics.ExposeOnREST {
		t.Errorf("shipped metrics config = %+v, want the dedicated port only", cfg.Metrics)
	}
	var prom struct {
		RuleFiles []string `yaml:"rule_files"`
		Scrape    []struct {
			Job    string `yaml:"job_name"`
			Static []struct {
				Targets []string `yaml:"targets"`
			} `yaml:"static_configs"`
		} `yaml:"scrape_configs"`
	}
	readYAML(t, monitoringDir+"prometheus/prometheus.yml", &prom)
	want := "tracker:" + strconv.Itoa(cfg.Metrics.Port)
	for _, s := range prom.Scrape {
		if s.Job == "tracker" && len(s.Static) == 1 && len(s.Static[0].Targets) == 1 && s.Static[0].Targets[0] == want {
			return
		}
	}
	t.Errorf("no tracker scrape job targeting %s", want)
}

func TestMonitoringConfig_Parses(t *testing.T) {
	for _, f := range []string{"alertmanager/alertmanager.yml", "grafana/provisioning/datasources/prometheus.yml",
		"grafana/provisioning/dashboards/bastion.yml"} {
		var v map[string]any
		readYAML(t, monitoringDir+f, &v)
	}
}

func readYAML(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
