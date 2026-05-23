// Package collector subscribes to NATS and delivers events to the Processor.
package collector

import (
	"encoding/json"
	"log"

	"github.com/nats-io/nats.go"

	"github.com/bastion/tracker/internal/models"
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

// Connect establishes a NATS connection and subscribes to all event subjects.
func Connect(url string, subjects []string, sink Sink) (*NATSCollector, error) {
	nc, err := nats.Connect(url,
		nats.MaxReconnects(10),
		nats.ReconnectWait(nats.DefaultReconnectWait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("[nats] disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Println("[nats] reconnected")
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
		log.Printf("[nats] subscribed to %s", subj)
	}
	return c, nil
}

func (c *NATSCollector) handle(msg *nats.Msg) {
	var ev models.BastionEvent
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		log.Printf("[nats] bad event on %s: %v", msg.Subject, err)
		return
	}
	c.sink.Process(ev)
}

// Close drains and closes the NATS connection.
func (c *NATSCollector) Close() {
	for _, sub := range c.subs {
		sub.Drain()
	}
	c.conn.Drain()
}
