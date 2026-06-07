// Package users provides an in-memory, thread-safe store for Tracker's admin
// user management. It is seeded from configuration at startup; runtime changes
// live in memory only — consistent with Tracker's PoC in-memory ring-buffer
// store — and reset on restart. PostgreSQL-backed persistence is a future target.
package users

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bastion/tracker/internal/config"
)

// Sentinel errors returned by the Manager. Handlers map these to HTTP statuses.
var (
	ErrNotFound      = errors.New("user not found")
	ErrExists        = errors.New("user already exists")
	ErrInvalidRole   = errors.New("invalid role: must be admin, operator or viewer")
	ErrEmptyName     = errors.New("user name must not be empty")
	ErrEmptyPassword = errors.New("password must not be empty")
	ErrLastAdmin     = errors.New("cannot remove or demote the last admin")
)

// validRole reports whether role is one Tracker recognises (mirrors auth.RoleLevel).
func validRole(role string) bool {
	switch role {
	case "admin", "operator", "viewer":
		return true
	}
	return false
}

// User is the public, password-free view of a managed user.
type User struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// record is the internal representation, including the credential.
type record struct {
	name string
	role string
	// secret holds either a bcrypt hash (managed/created users) or, for seed
	// users from config, possibly a plain-text password (PoC mode). hashed
	// distinguishes the two so Verify uses the right comparison.
	secret    string
	hashed    bool
	createdAt time.Time
	updatedAt time.Time
}

func (r *record) toUser() User {
	return User{Name: r.name, Role: r.role, CreatedAt: r.createdAt, UpdatedAt: r.updatedAt}
}

// Manager is a concurrency-safe collection of users.
type Manager struct {
	mu    sync.RWMutex
	users map[string]*record
}

// New builds a Manager seeded from the configured user list. Entries with an
// empty name are skipped.
func New(seed []config.UserConfig) *Manager {
	m := &Manager{users: make(map[string]*record)}
	now := time.Now()
	for _, u := range seed {
		if u.Name == "" {
			continue
		}
		m.users[u.Name] = &record{
			name:      u.Name,
			role:      u.Role,
			secret:    u.Password,
			hashed:    strings.HasPrefix(u.Password, "$2"),
			createdAt: now,
			updatedAt: now,
		}
	}
	return m
}

// List returns all users (password-free), sorted by name.
func (m *Manager) List() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, r := range m.users {
		out = append(out, r.toUser())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a single user, or ErrNotFound.
func (m *Manager) Get(name string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	return r.toUser(), nil
}

// Verify checks a name/password pair and returns the user's role on success.
// It accepts both bcrypt hashes and (for PoC seed users) plain-text passwords.
func (m *Manager) Verify(name, password string) (role string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, found := m.users[name]
	if !found {
		return "", false
	}
	if r.hashed {
		if bcrypt.CompareHashAndPassword([]byte(r.secret), []byte(password)) == nil {
			return r.role, true
		}
		return "", false
	}
	if r.secret == password {
		return r.role, true
	}
	return "", false
}

// Create adds a new user with a bcrypt-hashed password.
func (m *Manager) Create(name, password, role string) (User, error) {
	if strings.TrimSpace(name) == "" {
		return User{}, ErrEmptyName
	}
	if password == "" {
		return User{}, ErrEmptyPassword
	}
	if !validRole(role) {
		return User{}, ErrInvalidRole
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[name]; exists {
		return User{}, ErrExists
	}
	now := time.Now()
	r := &record{name: name, role: role, secret: string(hash), hashed: true, createdAt: now, updatedAt: now}
	m.users[name] = r
	return r.toUser(), nil
}

// UpdateRole changes a user's role. Demoting the last admin is refused.
func (m *Manager) UpdateRole(name, role string) (User, error) {
	if !validRole(role) {
		return User{}, ErrInvalidRole
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	if r.role == "admin" && role != "admin" && m.adminCountLocked() <= 1 {
		return User{}, ErrLastAdmin
	}
	r.role = role
	r.updatedAt = time.Now()
	return r.toUser(), nil
}

// SetPassword replaces a user's password with a fresh bcrypt hash.
func (m *Manager) SetPassword(name, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.users[name]
	if !ok {
		return ErrNotFound
	}
	r.secret = string(hash)
	r.hashed = true
	r.updatedAt = time.Now()
	return nil
}

// Delete removes a user. Removing the last admin is refused to avoid lockout.
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.users[name]
	if !ok {
		return ErrNotFound
	}
	if r.role == "admin" && m.adminCountLocked() <= 1 {
		return ErrLastAdmin
	}
	delete(m.users, name)
	return nil
}

// adminCountLocked counts admin users. Callers must hold the lock.
func (m *Manager) adminCountLocked() int {
	n := 0
	for _, r := range m.users {
		if r.role == "admin" {
			n++
		}
	}
	return n
}
