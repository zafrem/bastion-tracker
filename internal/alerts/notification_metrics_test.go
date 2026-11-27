package alerts_test

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/zafrem/bastion-tracker/internal/alerts"
	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/metrics"
	"github.com/zafrem/bastion-tracker/internal/models"
	"github.com/zafrem/bastion-tracker/internal/notify"
	"github.com/zafrem/bastion-tracker/internal/store"
)

type result struct{ err error }

func (r result) Notify(string, string, string) error { return r.err }

func TestNotificationDeliveryIsCounted(t *testing.T) {
	rules := []config.AlertRule{{Name: "n", Condition: "m.e", Severity: "warning", Channels: []string{"ok-channel", "broken-channel", "missing"}}}
	al := alerts.New(rules, store.New(10), map[string]notify.Notifier{
		"ok-channel": result{}, "broken-channel": result{errors.New("down")},
	})
	value := func(channel, res string) func() float64 {
		return func() float64 { return testutil.ToFloat64(metrics.Notifications.WithLabelValues(channel, res)) }
	}
	counts := []func() float64{value("ok-channel", "success"), value("broken-channel", "failure"), value(metrics.Other, "unknown_channel")}
	var before []float64
	for _, c := range counts {
		before = append(before, c())
	}

	al.Evaluate(models.BastionEvent{Module: "m", EventType: "e"})

	for i, c := range counts {
		for deadline := time.Now().Add(2 * time.Second); c() != before[i]+1; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("notification counter %d = %v, want %v", i, c(), before[i]+1)
			}
		}
	}
}
