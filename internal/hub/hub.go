// Package hub manages WebSocket connections and broadcasts events to all clients.
package hub

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true }, // allow all origins (PoC)
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

// clientFilter stores the per-client event filter set via a set_filter WebSocket message.
type clientFilter struct {
	Module   string `json:"module"`
	Severity string `json:"severity"`
	TenantID string `json:"tenant_id"`
}

type client struct {
	conn   *websocket.Conn
	send   chan []byte
	mu     sync.RWMutex
	filter *clientFilter
}

// allowsMessage returns true if the message passes the client's current filter.
func (c *client) allowsMessage(data []byte) bool {
	c.mu.RLock()
	f := c.filter
	c.mu.RUnlock()
	if f == nil {
		return true
	}
	// Quick JSON parse — only check fields present in the filter.
	var msg struct {
		Type    string `json:"type"`
		Payload struct {
			Module   string `json:"module"`
			Severity string `json:"severity"`
			TenantID string `json:"tenant_id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return true
	}
	if msg.Type != "event" {
		return true // only filter event messages
	}
	if f.Module != "" && msg.Payload.Module != f.Module {
		return false
	}
	if f.Severity != "" && msg.Payload.Severity != f.Severity {
		return false
	}
	if f.TenantID != "" && msg.Payload.TenantID != f.TenantID {
		return false
	}
	return true
}

// Subscription is a channel-based consumer for non-WebSocket callers (e.g. gRPC streaming).
type Subscription struct {
	ch chan []byte
}

// C returns the read-only channel that receives broadcast messages.
func (s *Subscription) C() <-chan []byte { return s.ch }

// Hub manages WebSocket clients, channel subscriptions, and broadcasting.
type Hub struct {
	mu            sync.RWMutex
	clients       map[*client]struct{}
	subs          map[*Subscription]struct{}
	broadcast     chan []byte
	register      chan *client
	unregister    chan *client
	subRegister   chan *Subscription
	subUnregister chan *Subscription
	bufferSize    int
}

// New creates and starts a Hub.
func New(bufferSize int) *Hub {
	if bufferSize <= 0 {
		bufferSize = 256
	}
	h := &Hub{
		clients:       make(map[*client]struct{}),
		subs:          make(map[*Subscription]struct{}),
		broadcast:     make(chan []byte, bufferSize),
		register:      make(chan *client),
		unregister:    make(chan *client),
		subRegister:   make(chan *Subscription),
		subUnregister: make(chan *Subscription),
		bufferSize:    bufferSize,
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()
			metrics.WebSocketConnections.Inc()

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			h.mu.Unlock()
			metrics.WebSocketConnections.Dec()

		case sub := <-h.subRegister:
			h.mu.Lock()
			h.subs[sub] = struct{}{}
			h.mu.Unlock()

		case sub := <-h.subUnregister:
			h.mu.Lock()
			if _, ok := h.subs[sub]; ok {
				delete(h.subs, sub)
				close(sub.ch)
			}
			h.mu.Unlock()

		case msg := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				if !c.allowsMessage(msg) {
					continue
				}
				select {
				case c.send <- msg:
				default:
					// Slow WebSocket consumer — drop to protect throughput.
				}
			}
			for sub := range h.subs {
				select {
				case sub.ch <- msg:
				default:
					// Slow channel consumer — drop.
				}
			}
			h.mu.RUnlock()
			metrics.WebSocketBroadcasts.Inc()
		}
	}
}

// Broadcast sends a WSMessage to all connected WebSocket clients and channel subscribers.
func (h *Hub) Broadcast(msg models.WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case h.broadcast <- data:
	default:
	}
}

// Subscribe registers a new channel-based subscriber and returns it.
func (h *Hub) Subscribe(bufSize int) *Subscription {
	if bufSize <= 0 {
		bufSize = h.bufferSize
	}
	sub := &Subscription{ch: make(chan []byte, bufSize)}
	h.subRegister <- sub
	return sub
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(sub *Subscription) {
	h.subUnregister <- sub
}

// ServeWS upgrades an HTTP connection to WebSocket and registers the client.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[hub] upgrade error: %v", err)
		return
	}

	c := &client{
		conn: conn,
		send: make(chan []byte, h.bufferSize),
	}
	h.register <- c

	go c.writePump()
	go c.readPump(h)
}

func (c *client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *client) readPump(h *Hub) {
	defer func() {
		h.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		var msg struct {
			Type     string       `json:"type"`
			Module   string       `json:"module"`
			Severity string       `json:"severity"`
			TenantID string       `json:"tenant_id"`
		}
		if json.Unmarshal(data, &msg) == nil && msg.Type == "set_filter" {
			c.mu.Lock()
			if msg.Module == "" && msg.Severity == "" && msg.TenantID == "" {
				c.filter = nil // clear filter
			} else {
				c.filter = &clientFilter{
					Module:   msg.Module,
					Severity: msg.Severity,
					TenantID: msg.TenantID,
				}
			}
			c.mu.Unlock()
		}
	}
}

// ConnectionCount returns the current number of connected WebSocket clients.
func (h *Hub) ConnectionCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// StartDashboardPush begins broadcasting dashboard summary updates every interval
// to all connected WebSocket clients. The supplied summaryFn is called once per
// interval to produce the current payload; it must be goroutine-safe.
// Stops when ctx is done.
func (h *Hub) StartDashboardPush(ctx interface{ Done() <-chan struct{} }, interval time.Duration, summaryFn func() models.WSMessage) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.Broadcast(summaryFn())
			case <-ctx.Done():
				return
			}
		}
	}()
}
