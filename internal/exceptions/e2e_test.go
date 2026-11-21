package exceptions

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// End-to-end over a real NATS server. Set EXCEPTIONS_E2E_NATS=host:port to run
// (CI starts a service container); otherwise the test is skipped.
//
// Each case uses its own Manager/Client pair, so they share the server but not
// state. Subjects are global, so cases run sequentially.
func natsURL(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("EXCEPTIONS_E2E_NATS")
	if addr == "" {
		t.Skip("EXCEPTIONS_E2E_NATS not set")
	}
	return "nats://" + addr
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestE2E_PushRevokeAndSnapshot(t *testing.T) {
	url := natsURL(t)
	priv, pub, _ := GenerateKeyPair()
	mgr, _ := NewManager(priv, filepath.Join(t.TempDir(), "t.json"), "")
	mgr.Connect(url)
	defer mgr.Close()

	// A module that is already running when the exception is created gets it pushed.
	live, _ := NewClient("sentinel", pub, filepath.Join(t.TempDir(), "live.json"))
	live.Start(url, 0)
	defer live.Close()
	time.Sleep(500 * time.Millisecond) // let the subscription and the empty snapshot settle

	e, err := mgr.Create(sample(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	rule := "sentinel.out.pii:email"
	waitFor(t, "pushed exception to apply", func() bool { _, ok := live.Allowed(rule, "acme", "u"); return ok })

	// A module that starts later catches up from the snapshot.
	late, _ := NewClient("sentinel", pub, filepath.Join(t.TempDir(), "late.json"))
	late.Start(url, 0)
	defer late.Close()
	waitFor(t, "late joiner to receive the snapshot", func() bool { _, ok := late.Allowed(rule, "acme", "u"); return ok })

	// A module for a different target never honours it.
	other, _ := NewClient("vault", pub, "")
	other.Start(url, 0)
	defer other.Close()
	time.Sleep(500 * time.Millisecond)
	if _, ok := other.Allowed(rule, "acme", "u"); ok {
		t.Error("vault honoured a sentinel-only exception")
	}

	// Revocation reaches both running modules.
	if _, err := mgr.Revoke(e.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revocation to reach live module", func() bool { _, ok := live.Allowed(rule, "acme", "u"); return !ok })
	waitFor(t, "revocation to reach late module", func() bool { _, ok := late.Allowed(rule, "acme", "u"); return !ok })
}

func TestE2E_ForgedMessagesOnTheBusAreIgnored(t *testing.T) {
	url := natsURL(t)
	_, pub, _ := GenerateKeyPair()
	c, _ := NewClient("sentinel", pub, "")
	c.Start(url, 0)
	defer c.Close()
	time.Sleep(500 * time.Millisecond)

	// An attacker on the bus signs with their own key.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Sign(attackerPriv, Payload{Kind: "update", IssuedAt: time.Now(), Exceptions: []Exception{{
		ID: "evil", Version: time.Now().UnixNano(), Rule: "sentinel.out.pii:email", Modules: []string{"sentinel"},
		TenantID: "acme", ExpiresAt: time.Now().Add(time.Hour)}}})
	data, _ := json.Marshal(env)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	_ = nc.Publish(SubjectUpdates, data)
	_ = nc.Publish(SubjectUpdates, []byte("not json"))
	_ = nc.Flush()
	time.Sleep(500 * time.Millisecond)
	if len(c.List()) != 0 {
		t.Error("a message signed by another key created an exception")
	}
}

func TestE2E_ModuleKeepsWorkingWhenTrackerGoesAway(t *testing.T) {
	url := natsURL(t)
	priv, pub, _ := GenerateKeyPair()
	mgr, _ := NewManager(priv, "", "")
	mgr.Connect(url)
	file := filepath.Join(t.TempDir(), "mod.json")
	c, _ := NewClient("sentinel", pub, file)
	c.Start(url, 0)
	time.Sleep(500 * time.Millisecond)
	if _, err := mgr.Create(sample(), "admin"); err != nil {
		t.Fatal(err)
	}
	rule := "sentinel.out.pii:email"
	waitFor(t, "exception to apply", func() bool { _, ok := c.Allowed(rule, "acme", "u"); return ok })

	// Tracker and the bus disappear for this module, and the module restarts.
	mgr.Close()
	c.Close()
	restarted, _ := NewClient("sentinel", pub, file) // no NATS URL: standalone
	restarted.Start("", 0)
	if _, ok := restarted.Allowed(rule, "acme", "u"); !ok {
		t.Error("module lost its exception when Tracker and NATS were unavailable")
	}
}
