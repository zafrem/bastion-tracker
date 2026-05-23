package demo

import (
	"sync"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// Recorder captures live events flowing through the processor into a replayable scenario.
type Recorder struct {
	mu        sync.Mutex
	state     models.RecordingState
	startedAt *time.Time
	stoppedAt *time.Time
	events    []models.DemoEvent
	scenario  *models.DemoScenario
	name      string
	desc      string
}

// NewRecorder creates a Recorder in idle state.
func NewRecorder() *Recorder {
	return &Recorder{state: models.RecordingIdle}
}

// Start begins a new recording session. Returns false if already recording.
func (rec *Recorder) Start(name, description string) bool {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.state == models.RecordingActive {
		return false
	}
	now := time.Now()
	rec.state = models.RecordingActive
	rec.startedAt = &now
	rec.stoppedAt = nil
	rec.events = nil
	rec.scenario = nil
	rec.name = name
	rec.desc = description
	return true
}

// Record appends a live event to the current recording. No-op when not active.
func (rec *Recorder) Record(ev models.BastionEvent) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.state != models.RecordingActive || rec.startedAt == nil {
		return
	}
	offset := ev.Timestamp.Sub(*rec.startedAt).Milliseconds()
	if offset < 0 {
		offset = 0
	}
	rec.events = append(rec.events, models.DemoEvent{OffsetMs: offset, Event: ev})
}

// Stop ends the recording and returns the captured scenario.
func (rec *Recorder) Stop() (models.DemoScenario, bool) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.state != models.RecordingActive {
		return models.DemoScenario{}, false
	}
	now := time.Now()
	rec.state = models.RecordingStopped
	rec.stoppedAt = &now

	var durSec float64
	if rec.startedAt != nil {
		durSec = now.Sub(*rec.startedAt).Seconds()
	}
	sc := models.DemoScenario{
		Name:        rec.name,
		Description: rec.desc,
		DurationSec: durSec,
		Events:      append([]models.DemoEvent{}, rec.events...),
	}
	rec.scenario = &sc
	return sc, true
}

// Status returns the current recording state.
func (rec *Recorder) Status() models.RecordingStatus {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	st := models.RecordingStatus{
		State:      rec.state,
		StartedAt:  rec.startedAt,
		StoppedAt:  rec.stoppedAt,
		EventCount: len(rec.events),
	}
	if rec.scenario != nil {
		cp := *rec.scenario
		st.Scenario = &cp
	}
	return st
}
