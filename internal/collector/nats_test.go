package collector_test

import (
	"testing"

	"github.com/zafrem/bastion-tracker/internal/collector"
	"github.com/zafrem/bastion-tracker/internal/models"
)

type discard struct{}

func (discard) Process(models.BastionEvent) {}

// If NATS is down when Tracker starts, it must keep trying rather than run without ingestion until restarted.
func TestConnect_KeepsTryingWhenNATSIsDown(t *testing.T) {
	c, err := collector.Connect("nats://127.0.0.1:1", []string{"bastion.events.>"}, discard{})
	if err != nil {
		t.Fatalf("Connect gave up instead of retrying in the background: %v", err)
	}
	c.Close()
}
