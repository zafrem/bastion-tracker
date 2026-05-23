// Package demo provides the demo scenario replay engine.
package demo

import (
	"fmt"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// EventSink receives events produced during replay.
type EventSink interface {
	Process(ev models.BastionEvent)
}

// WSBroadcaster sends arbitrary WebSocket messages (e.g. annotation events).
type WSBroadcaster interface {
	Broadcast(msg models.WSMessage)
}

// Engine manages demo scenario replay and synthetic event injection.
type Engine struct {
	mu          sync.Mutex
	scenarios   map[string]models.DemoScenario
	running     map[string]chan struct{} // scenario name → cancel channel
	sink        EventSink
	broadcaster WSBroadcaster // optional — used to emit annotations during replay
}

// New creates an Engine with the built-in scenarios loaded.
func NewEngine(sink EventSink) *Engine {
	e := &Engine{
		scenarios: make(map[string]models.DemoScenario),
		running:   make(map[string]chan struct{}),
		sink:      sink,
	}
	for _, s := range BuiltinScenarios() {
		e.scenarios[s.Name] = s
	}
	return e
}

// SetBroadcaster attaches a hub broadcaster so annotations are pushed during replay.
func (e *Engine) SetBroadcaster(b WSBroadcaster) {
	e.mu.Lock()
	e.broadcaster = b
	e.mu.Unlock()
}

// List returns all available scenarios.
func (e *Engine) List() []models.DemoScenario {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]models.DemoScenario, 0, len(e.scenarios))
	for _, s := range e.scenarios {
		out = append(out, s)
	}
	return out
}

// Get returns a named scenario.
func (e *Engine) Get(name string) (models.DemoScenario, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.scenarios[name]
	return s, ok
}

// Replay starts replaying a named scenario at the given speed multiplier
// (1.0 = real-time, 2.0 = twice as fast).  Returns an error if the scenario
// doesn't exist or is already running.
func (e *Engine) Replay(name string, speed float64) error {
	if speed <= 0 {
		speed = 1.0
	}

	e.mu.Lock()
	sc, ok := e.scenarios[name]
	if !ok {
		e.mu.Unlock()
		return fmt.Errorf("scenario %q not found", name)
	}
	if _, running := e.running[name]; running {
		e.mu.Unlock()
		return fmt.Errorf("scenario %q is already running", name)
	}
	cancel := make(chan struct{})
	e.running[name] = cancel
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, name)
			e.mu.Unlock()
		}()

		e.mu.Lock()
		broadcaster := e.broadcaster
		e.mu.Unlock()

		start := time.Now()

		// Build annotation schedule sorted by offset (scenarios keep them sorted).
		annIdx := 0
		anns := sc.Annotations

		for _, de := range sc.Events {
			targetOffset := time.Duration(float64(de.OffsetMs)/speed) * time.Millisecond
			fireAt := start.Add(targetOffset)

			// Emit any annotations that fall before this event.
			for annIdx < len(anns) {
				annOffset := time.Duration(float64(anns[annIdx].OffsetMs)/speed) * time.Millisecond
				annAt := start.Add(annOffset)
				if !annAt.Before(fireAt) {
					break
				}
				annDelay := time.Until(annAt)
				if annDelay > 0 {
					select {
					case <-cancel:
						return
					case <-time.After(annDelay):
					}
				}
				if broadcaster != nil {
					broadcaster.Broadcast(models.WSMessage{Type: "annotation", Payload: anns[annIdx]})
				}
				annIdx++
			}

			delay := time.Until(fireAt)
			if delay > 0 {
				select {
				case <-cancel:
					return
				case <-time.After(delay):
				}
			}
			select {
			case <-cancel:
				return
			default:
			}
			ev := de.Event
			ev.Timestamp = time.Now()
			e.sink.Process(ev)
		}
	}()
	return nil
}

// Stop cancels a running scenario replay.
func (e *Engine) Stop(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ch, ok := e.running[name]
	if ok {
		close(ch)
		delete(e.running, name)
	}
	return ok
}

// AddScenario registers (or replaces) a scenario in the engine.
func (e *Engine) AddScenario(sc models.DemoScenario) {
	e.mu.Lock()
	e.scenarios[sc.Name] = sc
	e.mu.Unlock()
}

// Inject immediately processes a single event (for manual injection / testing).
func (e *Engine) Inject(ev models.BastionEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	e.sink.Process(ev)
}

// ActiveScenarios returns the names of currently running scenarios.
func (e *Engine) ActiveScenarios() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make([]string, 0, len(e.running))
	for n := range e.running {
		names = append(names, n)
	}
	return names
}
