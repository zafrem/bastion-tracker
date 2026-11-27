package metrics

import (
	"runtime"
	"runtime/debug"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// StoreStats describes what the in-memory store holds.
type StoreStats struct {
	Events        int // events in the ring buffer
	EventCapacity int
	EventsWritten int // since start
	Traces        int
	LineageTraces int
	Incidents     map[string]int    // status → count
	Alerts        map[[2]string]int // {status, severity} → count
}

// MonitorStats describes the pipeline monitor.
type MonitorStats struct {
	Sessions            int
	PendingCheckpoints  int
	OldestPendingWaited time.Duration
}

// NATSStats describes one NATS connection.
type NATSStats struct {
	Client     string // what the connection is for, e.g. "collector"
	Connected  bool
	Reconnects uint64
	Received   uint64
	Dropped    uint64 // messages discarded because a subscription fell behind
	Pending    int    // messages waiting to be processed
}

// Sources provides current state. Nil entries are skipped.
type Sources struct {
	Version string
	Store   func() StoreStats
	Monitor func() MonitorStats
	NATS    []func() NATSStats
}

var (
	buildInfo   = desc("tracker_build_info", "Always 1; the labels identify the running build.", "version", "revision", "goversion")
	storeEvents = desc("tracker_store_events", "Events held in the in-memory ring buffer.")
	storeCap    = desc("tracker_store_event_capacity", "Size of the event ring buffer.")
	storeTotal  = desc("tracker_store_events_written_total", "Events written to the store since start.")
	storeTraces = desc("tracker_store_traces", "Traces held in memory.")
	storeLine   = desc("tracker_store_lineage_traces", "Traces with chunk lineage held in memory.")
	incidents   = desc("tracker_incidents", "Incidents held, by status.", "status")
	alertsByS   = desc("tracker_alerts", "Alerts held, by status and severity.", "status", "severity")
	activeAl    = desc("tracker_active_alerts", "Alerts that are firing: not yet acknowledged or resolved.")
	monSessions = desc("tracker_monitor_sessions", "Pipeline monitor sessions held in memory.")
	monPending  = desc("tracker_monitor_pending_checkpoints", "Gate-mode checkpoints waiting for a decision.")
	monOldest   = desc("tracker_monitor_oldest_pending_checkpoint_seconds", "How long the oldest pending checkpoint has waited.")
	natsUp      = desc("tracker_nats_connected", "1 while the NATS connection is up.", "client")
	natsReconn  = desc("tracker_nats_reconnects_total", "Times the NATS connection was re-established.", "client")
	natsRecv    = desc("tracker_nats_messages_received_total", "Messages received from NATS.", "client")
	natsDropped = desc("tracker_nats_messages_dropped_total", "Messages dropped because a subscription fell behind.", "client")
	natsPending = desc("tracker_nats_pending_messages", "Messages received but not yet processed.", "client")
)

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

type stateCollector struct{ src Sources }

// NewStateCollector reports the current state of Tracker's components each time it is scraped.
func NewStateCollector(src Sources) prometheus.Collector { return stateCollector{src} }

func (c stateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{buildInfo, storeEvents, storeCap, storeTotal, storeTraces, storeLine, incidents,
		alertsByS, activeAl, monSessions, monPending, monOldest, natsUp, natsReconn, natsRecv, natsDropped, natsPending} {
		ch <- d
	}
}

func (c stateCollector) Collect(ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
	}

	gauge(buildInfo, 1, c.src.Version, revision(), runtime.Version())

	if c.src.Store != nil {
		s := c.src.Store()
		gauge(storeEvents, float64(s.Events))
		gauge(storeCap, float64(s.EventCapacity))
		counter(storeTotal, float64(s.EventsWritten))
		gauge(storeTraces, float64(s.Traces))
		gauge(storeLine, float64(s.LineageTraces))
		for status, n := range s.Incidents {
			gauge(incidents, float64(n), status)
		}
		firing := 0
		for k, n := range s.Alerts {
			gauge(alertsByS, float64(n), k[0], k[1])
			if k[0] == "firing" {
				firing += n
			}
		}
		gauge(activeAl, float64(firing))
	}
	if c.src.Monitor != nil {
		m := c.src.Monitor()
		gauge(monSessions, float64(m.Sessions))
		gauge(monPending, float64(m.PendingCheckpoints))
		gauge(monOldest, m.OldestPendingWaited.Seconds())
	}
	for _, source := range c.src.NATS {
		n := source()
		up := 0.0
		if n.Connected {
			up = 1
		}
		gauge(natsUp, up, n.Client)
		counter(natsReconn, float64(n.Reconnects), n.Client)
		counter(natsRecv, float64(n.Received), n.Client)
		counter(natsDropped, float64(n.Dropped), n.Client)
		gauge(natsPending, float64(n.Pending), n.Client)
	}
}

func revision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}
