package collector

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/zafrem/bastion-tracker/internal/metrics"
	"github.com/zafrem/bastion-tracker/internal/models"
)

// fakeNATS speaks just enough of the NATS protocol to accept one client, record its subscription and send it
// messages. It lets the test take the server away and bring it back.
type fakeNATS struct {
	t    *testing.T
	addr string

	mu   sync.Mutex
	lis  net.Listener
	conn net.Conn
	sid  string
}

func (f *fakeNATS) start() {
	lis, err := net.Listen("tcp", f.addr)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.lis = lis
	f.mu.Unlock()
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
}

func (f *fakeNATS) serve(conn net.Conn) {
	f.mu.Lock()
	f.conn, f.sid = conn, ""
	fmt.Fprintf(conn, "INFO {\"server_id\":\"fake\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n")
	f.mu.Unlock()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		f.mu.Lock()
		switch strings.ToUpper(fields[0]) {
		case "PING":
			_, _ = io.WriteString(conn, "PONG\r\n")
		case "SUB":
			f.sid = fields[len(fields)-1]
		}
		f.mu.Unlock()
	}
}

func (f *fakeNATS) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.lis.Close()
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn, f.sid = nil, ""
	}
}

func (f *fakeNATS) publish(payload string) {
	waitFor(f.t, "the subscription", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.sid != ""
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	fmt.Fprintf(f.conn, "MSG bastion.events.test %s %s\r\n%s\r\n", f.sid, strconv.Itoa(len(payload)), payload)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

type sink chan models.BastionEvent

func (s sink) Process(ev models.BastionEvent) {
	if ev.EventType == "panic" {
		panic("test panic")
	}
	s <- ev
}

func freeAddr(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	return lis.Addr().String()
}

func TestCollector_ReportsOutagesAndRecovers(t *testing.T) {
	server := &fakeNATS{t: t, addr: freeAddr(t)}
	events := make(sink, 4)
	c, err := Connect("nats://"+server.addr, []string{"bastion.events.>"}, events)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if got := c.conn.Opts.MaxReconnect; got >= 0 {
		t.Errorf("the collector stops retrying after %d attempts; it must never give up", got)
	}
	if c.Stats().Connected {
		t.Fatal("reported as connected with no server")
	}
	receive := func(when string) {
		t.Helper()
		server.publish(`{"event_type":"hello","module":"vault"}`)
		select {
		case ev := <-events:
			if ev.EventType != "hello" {
				t.Errorf("%s: received %+v", when, ev)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no event delivered", when)
		}
	}

	server.start()
	waitFor(t, "the first connection", func() bool { return c.Stats().Connected })
	receive("after a late start")

	decodeErrors := testutil.ToFloat64(metrics.NATSDecodeErrors)
	panics := testutil.ToFloat64(metrics.Panics.WithLabelValues("nats"))
	server.publish("not json")
	server.publish(`{"event_type":"panic"}`)
	receive("after a bad message and a panic")
	if got := testutil.ToFloat64(metrics.NATSDecodeErrors) - decodeErrors; got != 1 {
		t.Errorf("decode errors counted = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.Panics.WithLabelValues("nats")) - panics; got != 1 {
		t.Errorf("panics counted = %v, want 1", got)
	}
	if got := c.Stats().Received; got < 4 {
		t.Errorf("messages received = %d, want at least 4", got)
	}

	server.stop()
	waitFor(t, "the outage to be reported", func() bool { return !c.Stats().Connected })
	server.start()
	defer server.stop()
	waitFor(t, "the reconnection", func() bool { st := c.Stats(); return st.Connected && st.Reconnects >= 1 })
	receive("after an outage")
}

func TestStats_WithoutACollectorShowsDisconnected(t *testing.T) {
	var c *NATSCollector
	if st := c.Stats(); st.Connected || st.Client != "collector" {
		t.Errorf("Stats() = %+v", st)
	}
}
