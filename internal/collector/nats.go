// Package collector subscribes to NATS and delivers events to the Processor.
package collector

import (
	"encoding/json"
	"log"
	"runtime/debug"

	"github.com/nats-io/nats.go"

	"github.com/zafrem/bastion-tracker/internal/metrics"
	"github.com/zafrem/bastion-tracker/internal/models"
)

// Sink receives decoded events.
type Sink interface {
	Process(ev models.BastionEvent)
}

// NATSCollector subscribes to bastion.events.> and forwards events to a Sink.
type NATSCollector struct {
	conn *nats.Conn
	subs []*nats.Subscription
	sink Sink
}

// Connect subscribes to the subjects. It does not require NATS to be up: the connection is retried for as long
// as Tracker runs, and the subscriptions take effect once it succeeds. An error means the settings are invalid.
func Connect(url string, subjects []string, sink Sink) (*NATSCollector, error) {
	nc, err := nats.Connect(url,
		nats.Name("bastion-tracker collector"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.IgnoreAuthErrorAbort(), // credentials may be fixed on the server while we retry
		nats.ReconnectWait(nats.DefaultReconnectWait),
		nats.ConnectHandler(func(_ *nats.Conn) {
			log.Println("[nats] connected")
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("[nats] disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Println("[nats] reconnected")
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Printf("[nats] error: %v", err)
		}),
	)
	if err != nil {
		return nil, err
	}

	c := &NATSCollector{conn: nc, sink: sink}
	for _, subj := range subjects {
		sub, err := nc.Subscribe(subj, c.handle)
		if err != nil {
			nc.Close()
			return nil, err
		}
		c.subs = append(c.subs, sub)
		log.Printf("[nats] subscribing to %s", subj)
	}
	return c, nil
}

func (c *NATSCollector) handle(msg *nats.Msg) {
	// A panic here would otherwise end the process.
	defer func() {
		if r := recover(); r != nil {
			metrics.Panics.WithLabelValues("nats").Inc()
			log.Printf("[nats] panic while processing a message: %v\n%s", r, debug.Stack()) // #nosec G706 -- panic value and stack
		}
	}()
	var ev models.BastionEvent
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		metrics.NATSDecodeErrors.Inc()
		log.Printf("[nats] bad event on %q: %q", msg.Subject, err.Error())
		return
	}
	c.sink.Process(ev)
}

// Stats describes the connection and its subscriptions, for monitoring.
func (c *NATSCollector) Stats() metrics.NATSStats {
	st := metrics.NATSStats{Client: "collector"}
	if c == nil {
		return st
	}
	conn := c.conn.Stats()
	st.Connected = c.conn.IsConnected()
	st.Reconnects = conn.Reconnects
	st.Received = conn.InMsgs
	for _, sub := range c.subs {
		if n, err := sub.Dropped(); err == nil && n > 0 {
			st.Dropped += uint64(n)
		}
		if n, _, err := sub.Pending(); err == nil {
			st.Pending += n
		}
	}
	return st
}

// Close drains and closes the NATS connection.
func (c *NATSCollector) Close() {
	for _, sub := range c.subs {
		_ = sub.Drain()
	}
	if err := c.conn.Drain(); err != nil {
		c.conn.Close()
	}
}
