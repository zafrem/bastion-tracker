package monitor

import (
	"testing"
	"time"

	"github.com/zafrem/bastion-tracker/internal/models"
)

func observed(trace string) models.BastionEvent {
	return models.BastionEvent{TraceID: trace, Module: "vault", EventType: "e", Timestamp: time.Now()}
}

func TestSessionsAndDecidedCheckpointsExpire(t *testing.T) {
	m := New(Config{Mode: ModeGate, SessionRetentionHours: 1})
	clock := time.Now()
	m.now = func() time.Time { return clock }

	m.ObserveEvent(observed("old"))
	decided := m.CreateCheckpoint("old", "t", "vault", nil)
	m.Decide(decided.CheckpointID, "op", "approve", "")
	waiting := m.CreateCheckpoint("old", "t", "vault", nil)

	clock = clock.Add(2 * time.Hour)
	m.ObserveEvent(observed("new"))

	sessions := m.ListSessions()
	if len(sessions) != 1 || sessions[0].TraceID != "new" {
		t.Errorf("sessions after the retention period = %+v, want only the new one", sessions)
	}
	if _, ok := m.GetCheckpoint(decided.CheckpointID); ok {
		t.Error("a checkpoint decided before the retention period is still held")
	}
	if _, ok := m.GetCheckpoint(waiting.CheckpointID); !ok {
		t.Error("a checkpoint still waiting for a decision was removed")
	}
}

func TestLeavingGateModeDecidesPendingCheckpoints(t *testing.T) {
	m := New(Config{Mode: ModeGate})
	cp := m.CreateCheckpoint("t", "t", "vault", nil)
	m.SetMode(ModeOff)
	got, _ := m.GetCheckpoint(cp.CheckpointID)
	if got.Status != StatusRejected || got.DecidedAt == nil {
		t.Errorf("checkpoint after leaving gate mode: status %s, decided %v", got.Status, got.DecidedAt)
	}
	if n := m.Stats().PendingCheckpoints; n != 0 {
		t.Errorf("pending checkpoints = %d, want 0", n)
	}
}
