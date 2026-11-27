package exceptions

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/zafrem/bastion-tracker/internal/metrics"
)

// KnownModules are the modules an exception may target.
var KnownModules = map[string]bool{"sentinel": true, "vault": true, "navigator": true, "anchor": true}

// Errors returned by Manager.
var (
	ErrDisabled = errors.New("exceptions are disabled: no signing key configured")
	ErrNotFound = errors.New("exception not found")
)

// GenerateKeyPair returns a base64 private key (for Tracker) and the matching
// base64 public key (for modules).
func GenerateKeyPair() (priv, pub string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(sk), base64.StdEncoding.EncodeToString(pk), nil
}

// Manager is Tracker's authoritative exception store. It signs and publishes
// every change and answers snapshot requests from modules.
type Manager struct {
	priv ed25519.PrivateKey
	path string

	mu      sync.Mutex
	byID    map[string]Exception
	lastVer int64
	nc      *nats.Conn
}

// ErrStateTampered is returned when Tracker's saved exception list does not
// verify. Tracker refuses to start rather than silently forget revocations.
var ErrStateTampered = errors.New("exceptions: saved state failed signature verification")

// NewManager builds a Manager. An empty privKeyB64 disables the feature.
//
// The saved list is itself signed, so editing the file by hand is detected.
// previousPubKeys (comma-separated, optional) lists the public keys of earlier
// signing keys, so state saved before a key rotation still loads; it is
// re-signed with the current key on the next save.
func NewManager(privKeyB64, path, previousPubKeys string) (*Manager, error) {
	m := &Manager{path: path, byID: map[string]Exception{}}
	if privKeyB64 == "" {
		return m, nil
	}
	raw, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("exceptions: signing key must be a base64 Ed25519 private key")
	}
	m.priv = ed25519.PrivateKey(raw)
	prev, err := ParsePublicKeys(previousPubKeys)
	if err != nil {
		return nil, err
	}
	if err := m.load(append([]ed25519.PublicKey{m.priv.Public().(ed25519.PublicKey)}, prev...)); err != nil {
		return nil, err
	}
	return m, nil
}

// Enabled reports whether a signing key is configured.
func (m *Manager) Enabled() bool { return m != nil && len(m.priv) > 0 }

// PublicKey is the base64 key modules need to verify exceptions.
func (m *Manager) PublicKey() string {
	if !m.Enabled() {
		return ""
	}
	return base64.StdEncoding.EncodeToString(m.priv.Public().(ed25519.PublicKey))
}

// Create validates, signs, stores and publishes a new exception.
func (m *Manager) Create(e Exception, actor string) (Exception, error) {
	if !m.Enabled() {
		return Exception{}, ErrDisabled
	}
	now := time.Now().UTC()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return Exception{}, err
	}
	e.ID = "exc-" + hex.EncodeToString(b)
	e.CreatedBy, e.CreatedAt = actor, now
	e.Revoked, e.RevokedBy, e.RevokedAt = false, "", time.Time{}
	e.Rule = strings.TrimSpace(e.Rule)
	if err := e.Validate(now); err != nil {
		return Exception{}, err
	}
	for _, mod := range e.Modules {
		if !KnownModules[mod] {
			return Exception{}, fmt.Errorf("unknown module %q", mod)
		}
	}
	// The rule namespace must name a module the exception targets, so an
	// exception cannot silently reach a module it was not written for.
	if i := strings.Index(e.Rule, "."); i > 0 {
		pfx, ok := e.Rule[:i], false
		for _, mod := range e.Modules {
			ok = ok || mod == pfx
		}
		if !ok {
			return Exception{}, fmt.Errorf("rule %q belongs to module %q, which is not in modules", e.Rule, pfx)
		}
	}
	m.mu.Lock()
	e.Version = m.nextVersion()
	m.byID[e.ID] = e
	m.persistLocked()
	m.mu.Unlock()
	m.publish("update", e)
	return e, nil
}

// Revoke marks an exception revoked and publishes the change. The revoked
// record is kept until it would have expired so replays cannot revive it.
func (m *Manager) Revoke(id, actor string) (Exception, error) {
	if !m.Enabled() {
		return Exception{}, ErrDisabled
	}
	m.mu.Lock()
	e, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return Exception{}, ErrNotFound
	}
	if !e.Revoked {
		e.Revoked, e.RevokedBy, e.RevokedAt = true, actor, time.Now().UTC()
		e.Version = m.nextVersion()
		m.byID[id] = e
		m.persistLocked()
	}
	m.mu.Unlock()
	m.publish("update", e)
	return e, nil
}

// List returns all exceptions, newest first.
func (m *Manager) List() []Exception {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Exception, 0, len(m.byID))
	for _, e := range m.byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Export returns a signed snapshot that can be copied into a module's
// exceptions file when that module has no connection to Tracker.
func (m *Manager) Export() (Envelope, error) {
	if !m.Enabled() {
		return Envelope{}, ErrDisabled
	}
	m.mu.Lock()
	cutoff := time.Now().Add(-24 * time.Hour)
	var list []Exception
	for _, e := range m.byID {
		if e.ExpiresAt.After(cutoff) {
			list = append(list, e)
		}
	}
	m.mu.Unlock()
	return Sign(m.priv, Payload{Kind: "snapshot", IssuedAt: time.Now().UTC(), Exceptions: list})
}

// nextVersion must be called with m.mu held.
func (m *Manager) nextVersion() int64 {
	v := time.Now().UnixNano()
	if v <= m.lastVer {
		v = m.lastVer + 1
	}
	m.lastVer = v
	return v
}

func (m *Manager) publish(kind string, es ...Exception) {
	m.mu.Lock()
	nc := m.nc
	m.mu.Unlock()
	if nc == nil {
		return // modules will catch up from a snapshot when they connect
	}
	env, err := Sign(m.priv, Payload{Kind: kind, IssuedAt: time.Now().UTC(), Exceptions: es})
	if err != nil {
		log.Printf("[exceptions] sign failed: %v", err)
		return
	}
	data, _ := json.Marshal(env)
	if err := nc.Publish(SubjectUpdates, data); err != nil {
		log.Printf("[exceptions] publish failed: %v", err)
	}
}

// Connect attaches to NATS: it answers snapshot requests and publishes
// changes. It never blocks startup; if NATS is down, changes are still stored
// and delivered through the snapshot when modules connect.
func (m *Manager) Connect(url string) {
	if !m.Enabled() || url == "" {
		return
	}
	nc, err := nats.Connect(url, nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1),
		nats.IgnoreAuthErrorAbort(), nats.ReconnectWait(5*time.Second))
	if err != nil {
		log.Printf("[exceptions] nats unavailable (%v); changes are stored but not pushed", err)
		return
	}
	_, err = nc.Subscribe(SubjectSnapshot, func(msg *nats.Msg) {
		env, err := m.Export()
		if err != nil {
			return
		}
		data, _ := json.Marshal(env)
		_ = msg.Respond(data)
	})
	if err != nil {
		log.Printf("[exceptions] snapshot responder failed: %v", err)
	}
	m.mu.Lock()
	m.nc = nc
	m.mu.Unlock()
}

// Stats describes the connection used to distribute exceptions, for monitoring.
func (m *Manager) Stats() metrics.NATSStats {
	st := metrics.NATSStats{Client: "exceptions"}
	m.mu.Lock()
	nc := m.nc
	m.mu.Unlock()
	if nc != nil {
		st.Connected = nc.IsConnected()
		st.Reconnects = nc.Stats().Reconnects
	}
	return st
}

// Close releases the NATS connection.
func (m *Manager) Close() {
	m.mu.Lock()
	nc := m.nc
	m.mu.Unlock()
	if nc != nil {
		nc.Close()
	}
}

func (m *Manager) load(keys []ed25519.PublicKey) error {
	if m.path == "" {
		return nil
	}
	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil // first run: nothing saved yet
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("%w: %v", ErrStateTampered, err)
	}
	p, err := Verify(keys, env)
	if err != nil {
		return fmt.Errorf("%w (%s): %v", ErrStateTampered, m.path, err)
	}
	for _, e := range p.Exceptions {
		m.byID[e.ID] = e
		if e.Version > m.lastVer {
			m.lastVer = e.Version
		}
	}
	// Re-sign with the current key (a no-op unless the key was rotated).
	m.mu.Lock()
	m.persistLocked()
	m.mu.Unlock()
	return nil
}

func (m *Manager) persistLocked() {
	if m.path == "" {
		return
	}
	list := make([]Exception, 0, len(m.byID))
	for _, e := range m.byID {
		list = append(list, e)
	}
	env, err := Sign(m.priv, Payload{Kind: "state", IssuedAt: time.Now().UTC(), Exceptions: list})
	var data []byte
	if err == nil {
		data, err = json.MarshalIndent(env, "", "  ")
	}
	if err == nil {
		err = writeFileAtomic(m.path, data)
	}
	if err != nil {
		log.Printf("[exceptions] could not persist %s: %v", m.path, err)
	}
}
