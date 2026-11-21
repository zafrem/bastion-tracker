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
	m, err := NewManager(priv, filepath.Join(t.TempDir(), "tracker-exc.json"), "")
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
		"unknown rule":    func(e *Exception) { e.Rule = "sentinel.format.skip" },
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
	m, _ := NewManager("", "", "")
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
	env.Payload = []byte(strings.Replace(string(env.Payload), `"acme"`, `"evil"`, 1))
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
	good0 := env
	file := filepath.Join(t.TempDir(), "exc.json")
	env.Payload = []byte(strings.Replace(string(env.Payload), "acme", "evil", 1)) // edit the signed content
	data, _ := json.Marshal([]Envelope{env})
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient("sentinel", pub, file)
	if len(c.List()) != 0 {
		t.Error("an edited file created exceptions")
	}
	// An exported envelope dropped in unchanged (air-gapped module) works.
	good, _ := json.Marshal(good0)
	_ = os.WriteFile(file, good, 0o600)
	c2, _ := NewClient("sentinel", pub, file)
	if _, ok := c2.Allowed("sentinel.out.pii:email", "acme", "u"); !ok {
		t.Error("exported envelope dropped into the file was not honoured")
	}
}

func TestManagerRestartKeepsVersionsMonotonic(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "t.json")
	m1, _ := NewManager(priv, path, "")
	e, _ := m1.Create(sample(), "admin")
	m2, _ := NewManager(priv, path, "")
	rev, err := m2.Revoke(e.ID, "admin")
	if err != nil || rev.Version <= e.Version {
		t.Fatalf("revocation after restart must carry a newer version: %v %v", err, rev.Version > e.Version)
	}
}

func TestTrackerStateFileIsSignedAndTamperEvident(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "state.json")
	m, _ := NewManager(priv, path, "")
	if _, err := m.Create(sample(), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(priv, path, ""); err != nil {
		t.Fatalf("untouched state must load: %v", err)
	}

	data, _ := os.ReadFile(path)
	var env Envelope
	_ = json.Unmarshal(data, &env)
	env.Payload = []byte(strings.Replace(string(env.Payload), `"acme"`, `"evil"`, 1))
	forged, _ := json.Marshal(env)
	_ = os.WriteFile(path, forged, 0o600)
	if _, err := NewManager(priv, path, ""); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("edited state must refuse to load, got %v", err)
	}

	// A plain, unsigned list (the way an attacker would write one) is refused too.
	_ = os.WriteFile(path, []byte(`[{"id":"x","rule":"sentinel.out.pii:a","tenant_id":"acme"}]`), 0o600)
	if _, err := NewManager(priv, path, ""); err == nil {
		t.Fatal("an unsigned state file must be refused")
	}
}

func TestKeyRotation(t *testing.T) {
	oldPriv, oldPub, _ := GenerateKeyPair()
	newPriv, newPub, _ := GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "state.json")

	// Exceptions issued under the old key.
	oldMgr, _ := NewManager(oldPriv, path, "")
	e, _ := oldMgr.Create(sample(), "admin")
	oldEnv, _ := oldMgr.Export()

	// Tracker moves to the new key; without the previous key its own state would not load.
	if _, err := NewManager(newPriv, path, ""); err == nil {
		t.Fatal("state saved under the old key must not load without previous_public_keys")
	}
	newMgr, err := NewManager(newPriv, path, oldPub)
	if err != nil {
		t.Fatalf("state must load with the previous key listed: %v", err)
	}
	if len(newMgr.List()) != 1 {
		t.Fatal("exception lost across rotation")
	}
	// ...and has been re-signed, so it now loads with the new key alone.
	if _, err := NewManager(newPriv, path, ""); err != nil {
		t.Fatalf("state should have been re-signed with the new key: %v", err)
	}

	// A module trusting only the old key rejects new-key messages; during
	// rotation it lists both and accepts old and new.
	oldOnly, _ := NewClient("sentinel", oldPub, "")
	both, _ := NewClient("sentinel", newPub+","+oldPub, "")
	rev, _ := newMgr.Revoke(e.ID, "admin")
	newEnv := envFor(t, newMgr, rev)
	if err := oldOnly.Apply(newEnv); err == nil {
		t.Error("a module that has not been given the new key must reject it")
	}
	if err := both.Apply(oldEnv); err != nil {
		t.Errorf("module listing both keys must accept the old key: %v", err)
	}
	if err := both.Apply(newEnv); err != nil {
		t.Errorf("module listing both keys must accept the new key: %v", err)
	}
	if _, ok := both.Allowed("sentinel.out.pii:email", "acme", "u"); ok {
		t.Error("revocation signed by the new key must apply")
	}
}

func TestKnownRule(t *testing.T) {
	for _, r := range []string{"sentinel.in:pi-001", "sentinel.out.pii:rule-1", "sentinel.out.permission",
		"sentinel.industry:hipaa", "vault.mask:email", "vault.view:email", "navigator.purpose:marketing", "anchor.bias:gender"} {
		if !KnownRule(r) {
			t.Errorf("%s should be a known rule", r)
		}
	}
	for _, r := range []string{"", "sentinel.in:", "navigator.tenant_isolation", "navigator.permission",
		"vault.permission", "sentinel.out.format", "anything"} {
		if KnownRule(r) {
			t.Errorf("%s must not be exemptable", r)
		}
	}
}
