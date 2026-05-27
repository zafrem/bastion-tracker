// tracker-cli is the main entry point for Bastion-Tracker.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	grpcsrv "github.com/bastion/tracker/internal/api/grpc"
	"github.com/bastion/tracker/internal/api/rest"
	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/bypass"
	"github.com/bastion/tracker/internal/cli"
	"github.com/bastion/tracker/internal/collector"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/demo"
	"github.com/bastion/tracker/internal/events"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/monitor"
	"github.com/bastion/tracker/internal/notify"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/store"
	"github.com/bastion/tracker/internal/validator"
)

func main() {
	root := cli.Root()

	for _, cmd := range root.Commands() {
		if cmd.Use == "server" {
			cmd.RunE = runServer
			break
		}
	}

	root.AddCommand(&cobra.Command{
		Use:   "demo-server",
		Short: "Start server and immediately run all demo scenarios",
		RunE:  runDemoServer,
	})

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildNotifiers constructs per-channel notifiers from configuration.
func buildNotifiers(cfg *config.AlertingConfig) map[string]notify.Notifier {
	notifiers := make(map[string]notify.Notifier)

	if cfg.Slack.WebhookURL != "" {
		notifiers["slack"] = &notify.SlackNotifier{WebhookURL: cfg.Slack.WebhookURL}
	}

	if cfg.Email.SMTPHost != "" && cfg.Email.From != "" && len(cfg.Email.To) > 0 {
		notifiers["email"] = &notify.EmailNotifier{
			SMTPHost: cfg.Email.SMTPHost,
			SMTPPort: cfg.Email.SMTPPort,
			From:     cfg.Email.From,
			To:       cfg.Email.To,
			Username: cfg.Email.Username,
			Password: cfg.Email.Password,
		}
	}

	if cfg.Webhook.URL != "" {
		notifiers["webhook"] = &notify.WebhookNotifier{URL: cfg.Webhook.URL}
	}

	return notifiers
}

func buildComponents(cfg *config.Config) (
	*store.Store,
	*hub.Hub,
	*processor.Processor,
	*demo.Engine,
	*alerts.Manager,
	*incidents.Manager,
	*honeytoken.Manager,
	*audit.Signer,
	*monitor.Manager,
) {
	s := store.New(cfg.Storage.MaxEventsMemory)
	h := hub.New(cfg.Realtime.BufferSize)
	notifiers := buildNotifiers(&cfg.Alerting)
	al := alerts.New(cfg.Alerting.Rules, s, notifiers)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	ht.SeedDefaults()
	proc := processor.New(s, h, al, inc, ht)

	// Audit signer — always enabled; uses built-in demo key if no secret configured.
	signer := audit.New(cfg.Storage.AuditSecret)
	proc.SetSigner(signer)

	// Schema validator.
	val := validator.New()
	proc.SetValidator(val)

	if cfg.BypassMonitor.Enabled {
		bm := bypass.New(cfg.BypassMonitor.SensitiveLabels, proc)
		proc.SetBypassMonitor(bm)
	}

	// Pipeline monitor — observe/gate modes.
	mon := monitor.New(monitor.Config{
		Mode:                  monitor.Mode(cfg.Monitor.Mode),
		SessionRetentionHours: cfg.Monitor.SessionRetentionHours,
		CheckpointTimeoutSec:  cfg.Monitor.CheckpointTimeoutSec,
		AutoApproveOnTimeout:  cfg.Monitor.AutoApproveOnTimeout,
	})
	// Attach the observe hook: every processed event is forwarded to the monitor.
	proc.AddHook(func(ev models.BastionEvent) { mon.ObserveEvent(ev) })
	// Wire WebSocket broadcast so operators see live step/checkpoint pushes.
	mon.SetBroadcast(func(v any) {
		if msg, ok := v.(models.WSMessage); ok {
			h.Broadcast(msg)
		}
	})

	demoEng := demo.NewEngine(proc)
	demoEng.SetBroadcaster(h)
	return s, h, proc, demoEng, al, inc, ht, signer, mon
}

func runServer(cmd *cobra.Command, args []string) error {
	cfgPath := cli.ServerConfigPath
	if cfgPath == "" {
		cfgPath = os.Getenv("CONFIG_PATH")
	}
	if cfgPath == "" {
		cfgPath = "./config/config.yaml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	s, h, proc, demoEng, al, inc, ht, signer, mon := buildComponents(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NATS (optional — falls back silently if unavailable).
	var natsCollector *collector.NATSCollector
	if cfg.NATS.URL != "" {
		nc, nerr := collector.Connect(cfg.NATS.URL, cfg.NATS.Subjects, proc)
		if nerr != nil {
			log.Printf("[nats] not connected (%v); running without NATS event ingestion", nerr)
		} else {
			natsCollector = nc
			log.Println("[nats] connected")
		}
		// Tracker also publishes its own events (incident_created, honey_token_alert, lineage_completed).
		pub := events.New(cfg.NATS.URL)
		proc.SetPublisher(pub)
	}

	restSrv := rest.New(s, h, proc, demoEng, al, inc, ht, &cfg.Auth, signer, mon, cfg.Server.RESTPort)
	grpcSrv := grpcsrv.New(s, proc, h, cfg.Server.GRPCPort)

	go al.StartBackgroundTasks(ctx)

	errCh := make(chan error, 2)
	go func() { errCh <- restSrv.Start(ctx) }()
	go func() { errCh <- grpcSrv.Start(ctx) }()

	authStatus := "disabled"
	if cfg.Auth.Enabled {
		authStatus = "enabled"
	}
	fmt.Printf("Bastion-Tracker v%s ready\n", cfg.Version)
	fmt.Printf("  REST/UI  → http://localhost:%d\n", cfg.Server.RESTPort)
	fmt.Printf("  gRPC     → localhost:%d\n", cfg.Server.GRPCPort)
	fmt.Printf("  Auth     → %s\n", authStatus)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		cancel()
		if natsCollector != nil {
			natsCollector.Close()
		}
		return err
	case <-sig:
		cancel()
		if natsCollector != nil {
			natsCollector.Close()
		}
		return nil
	}
}

func runDemoServer(cmd *cobra.Command, args []string) error {
	cfg := config.Defaults()
	s, h, proc, demoEng, al, inc, ht, signer, mon := buildComponents(cfg)

	restSrv := rest.New(s, h, proc, demoEng, al, inc, ht, &cfg.Auth, signer, mon, cfg.Server.RESTPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go al.StartBackgroundTasks(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- restSrv.Start(ctx) }()

	fmt.Printf("Bastion-Tracker demo-server ready → http://localhost:%d\n", cfg.Server.RESTPort)
	fmt.Println("Running all demo scenarios…")

	for _, sc := range demoEng.List() {
		if err := demoEng.Replay(sc.Name, 2.0); err != nil {
			log.Printf("scenario %s: %v", sc.Name, err)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-sig:
		cancel()
		return nil
	}
}
