package demo

import (
	"sync"
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

type fakeSink struct {
	mu     sync.Mutex
	events []models.BastionEvent
}

func (f *fakeSink) Process(ev models.BastionEvent) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
}

func (f *fakeSink) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func TestNewEngine_LoadsBuiltinScenarios(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	scenarios := eng.List()
	if len(scenarios) == 0 {
		t.Error("expected built-in scenarios to be loaded")
	}
}

func TestReplay_UnknownScenario_ReturnsError(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	if err := eng.Replay("no-such-scenario", 1); err == nil {
		t.Error("expected error for unknown scenario")
	}
}

func TestReplay_DeliverEvents(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	// Use the smallest scenario (prompt injection — 3 events) at very fast speed.
	if err := eng.Replay("02-prompt-injection", 100); err != nil {
		t.Fatal(err)
	}
	// Wait up to 3 seconds for all events.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if sink.Count() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sink.Count() < 3 {
		t.Errorf("expected ≥3 events, got %d", sink.Count())
	}
}

func TestReplay_DuplicateScenario_ReturnsError(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	if err := eng.Replay("01-normal-flow", 0.01); err != nil {
		t.Fatal(err)
	}
	if err := eng.Replay("01-normal-flow", 1); err == nil {
		t.Error("expected error for duplicate replay")
	}
	eng.Stop("01-normal-flow")
}

func TestStop_CancelsReplay(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	if err := eng.Replay("01-normal-flow", 0.001); err != nil { // very slow
		t.Fatal(err)
	}
	countBefore := sink.Count()
	eng.Stop("01-normal-flow")
	time.Sleep(100 * time.Millisecond)
	countAfter := sink.Count()
	// After stopping, no new events should arrive.
	time.Sleep(200 * time.Millisecond)
	if sink.Count() > countAfter {
		t.Error("events continued after Stop()")
	}
	_ = countBefore
}

func TestInject_ImmediatelyProcesses(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	ev := models.BastionEvent{Module: "test", EventType: "injected"}
	eng.Inject(ev)
	if sink.Count() != 1 {
		t.Errorf("expected 1 event after inject, got %d", sink.Count())
	}
}

func TestInject_SetsTimestampIfZero(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	eng.Inject(models.BastionEvent{Module: "test"})
	if sink.events[0].Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestBuiltinScenarios_AllHaveEvents(t *testing.T) {
	for _, sc := range BuiltinScenarios() {
		if len(sc.Events) == 0 {
			t.Errorf("scenario %q has no events", sc.Name)
		}
	}
}

func TestGet_KnownScenario(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	sc, ok := eng.Get("01-normal-flow")
	if !ok {
		t.Error("expected 01-normal-flow to exist")
	}
	if sc.Name != "01-normal-flow" {
		t.Errorf("unexpected name: %s", sc.Name)
	}
}

func TestGet_UnknownScenario(t *testing.T) {
	sink := &fakeSink{}
	eng := NewEngine(sink)
	_, ok := eng.Get("does-not-exist")
	if ok {
		t.Error("expected not ok for unknown scenario")
	}
}
