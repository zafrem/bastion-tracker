// Package cli defines the tracker-cli commands.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"

	"github.com/bastion/tracker/internal/models"
)

var baseURL string

// Root returns the root cobra command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "tracker-cli",
		Short: "Bastion-Tracker CLI",
	}
	root.PersistentFlags().StringVar(&baseURL, "api", "http://localhost:8080", "Tracker API base URL")
	root.AddCommand(serverCmd(), streamCmd(), tracesCmd(), traceCmd(), securityCmd(), demoCmd(), injectCmd(), generateCmd())
	return root
}

// ─── Server command (delegates to main for wiring) ───────────────────────────

func serverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Start the Tracker server",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("tracker-cli server: use main.go runServer()")
			return nil
		},
	}
}

// ─── Stream ───────────────────────────────────────────────────────────────────

func streamCmd() *cobra.Command {
	var module, severity string
	cmd := &cobra.Command{
		Use:   "stream",
		Short: "Stream live events from Tracker WebSocket",
		RunE: func(cmd *cobra.Command, args []string) error {
			wsURL := strings.Replace(baseURL, "http://", "ws://", 1) + "/ws/events"
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()
			fmt.Println("═══════════════════════════════════════════")
			fmt.Println("  Bastion-Tracker Live Event Stream")
			fmt.Println("  Press Ctrl+C to stop")
			fmt.Println("═══════════════════════════════════════════")

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() { <-sig; conn.Close() }()

			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					break
				}
				var wsMsg models.WSMessage
				if err := json.Unmarshal(msg, &wsMsg); err != nil {
					continue
				}
				if wsMsg.Type != "event" {
					continue
				}
				data, _ := json.Marshal(wsMsg.Payload)
				var ev models.BastionEvent
				if err := json.Unmarshal(data, &ev); err != nil {
					continue
				}
				if module != "" && ev.Module != module {
					continue
				}
				if severity != "" && ev.Severity != severity {
					continue
				}
				ts := ev.Timestamp.Format("15:04:05.000")
				icon := severityIcon(ev.Severity)
				fmt.Printf("%s %s [%s] %s", ts, icon, padRight(ev.Module, 10), ev.EventType)
				if ev.DurationMs > 0 {
					fmt.Printf(" (%dms)", ev.DurationMs)
				}
				if ev.TenantID != "" {
					fmt.Printf(" tenant=%s", ev.TenantID)
				}
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&module, "module", "", "Filter by module (sentinel, vault, navigator, anchor)")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severity (info, warning, error, critical)")
	return cmd
}

// ─── Traces ───────────────────────────────────────────────────────────────────

func tracesCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "traces",
		Short: "List recent request traces",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(fmt.Sprintf("/v1/traces?limit=%d", limit))
			if err != nil {
				return err
			}
			var r models.TracesResponse
			if err := json.Unmarshal(resp, &r); err != nil {
				return err
			}
			fmt.Printf("%-38s %-10s %-10s %-12s %s\n", "TRACE ID", "PIPELINE", "STATUS", "TOTAL (ms)", "TIME")
			fmt.Println(strings.Repeat("─", 80))
			for _, tr := range r.Traces {
				ts := tr.StartTime.Format("15:04:05")
				fmt.Printf("%-38s %-10s %-10s %-12d %s\n",
					tr.TraceID, tr.PipelineType, tr.Status, tr.TotalMs, ts)
			}
			fmt.Printf("\n%d trace(s)\n", r.Total)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "Number of traces to show")
	return cmd
}

func traceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trace <trace_id>",
		Short: "Show detail for a single trace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet("/v1/traces/" + args[0])
			if err != nil {
				return err
			}
			var tr models.Trace
			if err := json.Unmarshal(resp, &tr); err != nil {
				return err
			}
			fmt.Println("═══════════════════════════════════════════")
			fmt.Printf("  Request Trace: %s\n", tr.TraceID)
			fmt.Println("═══════════════════════════════════════════")
			fmt.Printf("Total Time : %dms\n", tr.TotalMs)
			fmt.Printf("Pipeline   : %s\n", tr.PipelineType)
			fmt.Printf("Status     : %s\n", tr.Status)
			fmt.Printf("Tenant     : %s\n", tr.TenantID)
			fmt.Println()
			for _, span := range tr.Spans {
				icon := "✅"
				if span.Status == "blocked" || span.Status == "error" {
					icon = "🚫"
				}
				fmt.Printf("  %-12s  [%4dms]  %s  %s\n", span.Module, span.DurationMs, icon, span.EventType)
			}
			return nil
		},
	}
}

// ─── Security ─────────────────────────────────────────────────────────────────

func securityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Security events and incident management",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "incidents",
			Short: "List open incidents",
			RunE: func(cmd *cobra.Command, args []string) error {
				resp, err := apiGet("/v1/security/incidents?status=open")
				if err != nil {
					return err
				}
				fmt.Println(string(resp))
				return nil
			},
		},
		&cobra.Command{
			Use:   "alerts",
			Short: "List firing alerts",
			RunE: func(cmd *cobra.Command, args []string) error {
				resp, err := apiGet("/v1/alerts?status=firing")
				if err != nil {
					return err
				}
				fmt.Println(string(resp))
				return nil
			},
		},
	)
	return cmd
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

func demoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Demo scenario management",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available demo scenarios",
			RunE: func(cmd *cobra.Command, args []string) error {
				resp, err := apiGet("/v1/demo/scenarios")
				if err != nil {
					return err
				}
				var scenarios []models.DemoScenario
				if err := json.Unmarshal(resp, &scenarios); err != nil {
					return err
				}
				fmt.Println("═══════════════════════════════════════════")
				fmt.Println("  Available Demo Scenarios")
				fmt.Println("═══════════════════════════════════════════")
				for _, s := range scenarios {
					fmt.Printf("  %-30s %s\n", s.Name, s.Description)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "replay <scenario-name>",
			Short: "Replay a demo scenario",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				body, _ := json.Marshal(map[string]interface{}{"name": args[0], "speed": 1.0})
				resp, err := apiPost("/v1/demo/replay", body)
				if err != nil {
					return err
				}
				fmt.Println(string(resp))
				return nil
			},
		},
	)
	return cmd
}

// ─── Inject ───────────────────────────────────────────────────────────────────

func injectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inject",
		Short: "Inject a synthetic event",
	}
	var module, eventType, tenantID, pipeline string
	cmd.Flags().StringVar(&module, "module", "sentinel", "Source module")
	cmd.Flags().StringVar(&eventType, "event-type", "request_received", "Event type")
	cmd.Flags().StringVar(&tenantID, "tenant", "demo-tenant", "Tenant ID")
	cmd.Flags().StringVar(&pipeline, "pipeline", "full", "Pipeline type")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ev := models.BastionEvent{
			Module:       module,
			EventType:    eventType,
			Severity:     "info",
			Timestamp:    time.Now(),
			TenantID:     tenantID,
			PipelineType: pipeline,
			Status:       "passed",
		}
		body, _ := json.Marshal(ev)
		resp, err := apiPost("/v1/demo/inject", body)
		if err != nil {
			return err
		}
		fmt.Println(string(resp))
		return nil
	}
	return cmd
}

// ─── Generate ────────────────────────────────────────────────────────────────

func generateCmd() *cobra.Command {
	var rate int
	var duration time.Duration
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate synthetic event traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Generating ~%d events/s for %s...\n", rate, duration)
			ticker := time.NewTicker(time.Second / time.Duration(rate))
			stop := time.After(duration)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT)
			modules := []string{"sentinel", "vault", "navigator", "anchor"}
			events := []string{"request_received", "validation_passed", "search_completed", "embedding_secured"}
			pipelines := []string{"full", "lite", "minimal"}
			i := 0
			for {
				select {
				case <-stop:
					fmt.Println("Done.")
					return nil
				case <-sig:
					return nil
				case <-ticker.C:
					ev := models.BastionEvent{
						Module:       modules[i%len(modules)],
						EventType:    events[i%len(events)],
						Severity:     "info",
						Timestamp:    time.Now(),
						TenantID:     "demo-tenant",
						PipelineType: pipelines[i%len(pipelines)],
						Status:       "passed",
						DurationMs:   int64(10 + i%90),
					}
					body, _ := json.Marshal(ev)
					apiPost("/v1/events", body) //nolint:errcheck
					i++
				}
			}
		},
	}
	cmd.Flags().IntVar(&rate, "rate", 10, "Events per second")
	cmd.Flags().DurationVar(&duration, "duration", 30*time.Second, "How long to generate")
	return cmd
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func apiGet(path string) ([]byte, error) {
	resp, err := http.Get(baseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func apiPost(path string, body []byte) ([]byte, error) {
	resp, err := http.Post(baseURL+path, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🚨"
	case "error":
		return "❌"
	case "warning":
		return "⚠️ "
	default:
		return "ℹ️ "
	}
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s[:n]
}
