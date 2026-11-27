package alerts_test

import (
	"sync"
	"testing"

	"github.com/zafrem/bastion-tracker/internal/alerts"
	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/incidents"
	"github.com/zafrem/bastion-tracker/internal/models"
	"github.com/zafrem/bastion-tracker/internal/store"
)

// Events arrive from NATS, REST and gRPC at once. Two alerts or incidents with one ID overwrite each other,
// so some would disappear from the dashboard and from the counts monitoring reports.
func TestConcurrentEvents_EveryAlertAndIncidentIsKept(t *testing.T) {
	s := store.New(10)
	al := alerts.New([]config.AlertRule{{Name: "r", Condition: "vault.cross_tenant_attempt", Severity: "critical"}}, s, nil)
	inc := incidents.New(s)

	const n = 500
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := models.BastionEvent{Module: "vault", EventType: "cross_tenant_attempt", Severity: "critical"}
			al.Evaluate(ev)
			inc.AutoCreate(ev)
		}()
	}
	wg.Wait()

	if got := len(s.ListAlerts("")); got != n {
		t.Errorf("stored %d alerts, want %d", got, n)
	}
	if got := len(s.ListIncidents("")); got != n {
		t.Errorf("stored %d incidents, want %d", got, n)
	}
}
