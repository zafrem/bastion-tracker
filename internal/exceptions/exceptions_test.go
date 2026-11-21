package exceptions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newPair(t *testing.T) (*Manager, string) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(priv, filepath.Join(t.TempDir(), "tracker-exc.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m, pub
}

func sample() Exception {
	return Exception{
		Rule: "sentinel.out.pii:email", Modules: []string{"sentinel"},
		TenantID: "acme", Justification: "support team needs emails",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func envFor(t *testing.T, m *Manager, es ...Exception) Envelope {
	t.Helper()
	env, err := Sign(m.priv, Payload{Kind: "update", IssuedAt: time.Now(), Exceptions: es})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestValidate(t *testing.T) {
	m, _ := newPair(t)
	bad := map[string]func(*Exception){
		"wildcard rule":   func(e *Exception) { e.Rule = "sentinel.*" },
		"no tenant":       func(e *Exception) { e.TenantID = "" },
		"short reason":    func(e *Exception) { e.Justification = "x" },
		"already expired": func(e *Exception) { e.ExpiresAt = time.Now().Add(-time.Hour) },
		"too long":        func(e *Exception) { e.ExpiresAt = time.Now().Add(MaxLifetime + 24*time.Hour) },
		"no module":       func(e *Exception) { e.Modules = nil },
		"unknown module":  func(e *Exception) { e.Modules = []string{"sentinel", "nope"} },
		"rule/module mismatch": func(e *Exception) {
			e.Rule = "vault.mask:email"
		},
	}
	for name, mutate := range bad {
		e := sample()
		mutate(&e)
		if _, err := m.Create(e, "admin"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := m.Create(sample(), "admin"); err != nil {
		t.Fatalf("valid exception rejected: %v", err)
	}
}

func TestDisabledWithoutKeys(t *testing.T) {
	m, _ := NewManager("", "")
	if _, err := m.Create(sample(), "a"); err != ErrDisabled {
		t.Errorf("got %v, want ErrDisabled", err)
	}
	c, err := NewClient("sentinel", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "u"); ok {
		t.Error("a client with no public key must never exempt anything")
	}
}

func TestClientEnforcesScope(t *testing.T) {
	m, pub := newPair(t)
	e, err := m.Create(sample(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient("sentinel", pub, "")
	env, _ := m.Export()
	if err := c.Apply(env); err != nil {
		t.Fatal(err)
	}
	if id, ok := c.Allowed("sentinel.out.pii:email", "acme", "anyone"); !ok || id != e.ID {
		t.Fatalf("expected exemption, got %q %v", id, ok)
	}
	for _, tc := range []struct{ rule, tenant string }{
		{"sentinel.out.pii:phone", "acme"},  // other rule
		{"sentinel.out.pii:email", "other"}, // other tenant
	} {
		if _, ok := c.Allowed(tc.rule, tc.tenant, "u"); ok {
			t.Errorf("exemption leaked to %+v", tc)
		}
	}
	// A different module must not honour a sentinel-only exception.
	v, _ := NewClient("vault", pub, "")
	_ = v.Apply(env)
	if _, ok := v.Allowed("sentinel.out.pii:email", "acme", "u"); ok {
		t.Error("vault honoured a sentinel-only exception")
	}
}

func TestUserScopeAndExpiry(t *testing.T) {
	m, pub := newPair(t)
	e := sample()
	e.UserID = "alice"
	if _, err := m.Create(e, "admin"); err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient("sentinel", pub, "")
	env, _ := m.Export()
	_ = c.Apply(env)
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "bob"); ok {
		t.Error("user-scoped exception applied to another user")
	}
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "alice"); !ok {
		t.Error("user-scoped exception did not apply to its user")
	}
	// Modules judge expiry themselves, without trusting Tracker.
	expired := Exception{ID: "x", Version: time.Now().UnixNano(), Rule: "sentinel.in:r1", Modules: []string{"sentinel"},
		TenantID: "acme", ExpiresAt: time.Now().Add(-time.Second)}
	if expired.Applies("sentinel", "sentinel.in:r1", "acme", "u", time.Now()) {
		t.Error("expired exception applied")
	}
}

func TestRejectsForgedAndTamperedEnvelopes(t *testing.T) {
	m, pub := newPair(t)
	other, _ := newPair(t) // attacker with their own key
	c, _ := NewClient("sentinel", pub, "")

	e := sample()
	e.ID, e.Version = "forged", time.Now().UnixNano()
	if err := c.Apply(envFor(t, other, e)); err == nil {
		t.Error("envelope signed by a different key was accepted")
	}

	if _, err := m.Create(sample(), "admin"); err != nil {
		t.Fatal(err)
	}
	env, _ := m.Export()
	env.Payload = json.RawMessage(strings.Replace(string(env.Payload), `"acme"`, `"evil"`, 1))
	if err := c.Apply(env); err == nil {
		t.Error("tampered payload was accepted")
	}
	if len(c.List()) != 0 {
		t.Error("rejected envelopes must leave no state")
	}
}

func TestReplayCannotUndoRevocation(t *testing.T) {
	m, pub := newPair(t)
	e, _ := m.Create(sample(), "admin")
	created := envFor(t, m, e)
	c, _ := NewClient("sentinel", pub, "")
	_ = c.Apply(created)
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "u"); !ok {
		t.Fatal("setup: exception should be active")
	}
	rev, err := m.Revoke(e.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Apply(envFor(t, m, rev))
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "u"); ok {
		t.Fatal("revoked exception still applies")
	}
	_ = c.Apply(created) // attacker replays the old, validly signed message
	if _, ok := c.Allowed("sentinel.out.pii:email", "acme", "u"); ok {
		t.Fatal("replayed envelope revived a revoked exception")
	}
}

func TestPersistenceSurvivesRestartWithoutTracker(t *testing.T) {
	m, pub := newPair(t)
	if _, err := m.Create(sample(), "admin"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "exc.json")
	c1, _ := NewClient("sentinel", pub, file)
	env, _ := m.Export()
	if err := c1.Apply(env); err != nil {
		t.Fatal(err)
	}
	// "Restart": a fresh client, no NATS, no Tracker, only the file.
	c2, _ := NewClient("sentinel", pub, file)
	if _, ok := c2.Allowed("sentinel.out.pii:email", "acme", "u"); !ok {
		t.Fatal("exception was not restored from the local file")
	}
}

func TestEditedFileGrantsNothing(t *testing.T) {
	m, pub := newPair(t)
	_, _ = m.Create(sample(), "admin")
	env, _ := m.Export()
	file := filepath.Join(t.TempDir(), "exc.json")
	data, _ := json.Marshal([]Envelope{env})
	data = []byte(strings.Replace(string(data), "acme", "evil", 1)) // JSON-escaped payload edit
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient("sentinel", pub, file)
	if len(c.List()) != 0 {
		t.Error("an edited file created exceptions")
	}
	// An exported envelope dropped in unchanged (air-gapped module) works.
	good, _ := json.Marshal(env)
	_ = os.WriteFile(file, good, 0o600)
	c2, _ := NewClient("sentinel", pub, file)
	if _, ok := c2.Allowed("sentinel.out.pii:email", "acme", "u"); !ok {
		t.Error("exported envelope dropped into the file was not honoured")
	}
}

func TestManagerRestartKeepsVersionsMonotonic(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "t.json")
	m1, _ := NewManager(priv, path)
	e, _ := m1.Create(sample(), "admin")
	m2, _ := NewManager(priv, path)
	rev, err := m2.Revoke(e.ID, "admin")
	if err != nil || rev.Version <= e.Version {
		t.Fatalf("revocation after restart must carry a newer version: %v %v", err, rev.Version > e.Version)
	}
}
