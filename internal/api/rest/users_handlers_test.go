package rest

// Tests for the admin user-management endpoints and the user-store-backed Login.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/demo"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/monitor"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/store"
	"github.com/bastion/tracker/internal/validator"
)

// newUserFixture builds a server seeded with three users. authCfg is supplied so
// the user store is populated; Enabled is false so the admin routes stay open
// (adminOrOpen) and can be exercised without a token.
func newUserFixture(t *testing.T, enabled bool) *testFixture {
	t.Helper()
	s := store.New(1000)
	h := hub.New(64)
	al := alerts.New(nil, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	proc := processor.New(s, h, al, inc, ht)
	proc.SetValidator(validator.New())
	demoEng := demo.NewEngine(proc)
	signer := audit.New("")
	mon := monitor.New(monitor.Config{Mode: monitor.ModeOff})
	proc.AddHook(func(ev models.BastionEvent) { mon.ObserveEvent(ev) })

	authCfg := &config.AuthConfig{
		Enabled:   enabled,
		JWTSecret: "test-secret",
		JWTExpiry: "1h",
		Users: []config.UserConfig{
			{Name: "admin", Password: "admin", Role: "admin"},
			{Name: "ops", Password: "ops", Role: "operator"},
			{Name: "viewer", Password: "viewer", Role: "viewer"},
		},
	}
	srv := New(s, h, proc, demoEng, al, inc, ht, authCfg, signer, mon, nil, 0)
	return &testFixture{handler: srv.httpServer.Handler, store: s, honey: ht, inc: inc, mon: mon, proc: proc}
}

// loginToken logs in and returns the issued JWT (used when auth is enabled).
func (f *testFixture) loginToken(t *testing.T, user, pass string) string {
	t.Helper()
	w := f.post(t, "/v1/auth/login", models.LoginRequest{Username: user, Password: pass})
	mustStatus(t, w, http.StatusOK)
	var lr models.LoginResponse
	decodeBody(t, w, &lr)
	return lr.Token
}

// doAuth issues a request with an Authorization: Bearer header.
func (f *testFixture) doAuth(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func TestListUsers(t *testing.T) {
	f := newUserFixture(t, false)
	w := f.get(t, "/v1/users")
	mustStatus(t, w, http.StatusOK)
	var got []map[string]any
	decodeBody(t, w, &got)
	if len(got) != 3 {
		t.Fatalf("expected 3 users, got %d", len(got))
	}
	// Passwords must never be serialized.
	for _, u := range got {
		if _, leaked := u["password"]; leaked {
			t.Fatalf("password leaked in user listing: %v", u)
		}
		if _, leaked := u["secret"]; leaked {
			t.Fatalf("secret leaked in user listing: %v", u)
		}
	}
}

func TestCreateUser_Then_Login(t *testing.T) {
	f := newUserFixture(t, true) // auth enabled so Login works
	token := f.loginToken(t, "admin", "admin")
	resp := f.doAuth(t, http.MethodPost, "/v1/users", models.CreateUserRequest{Name: "alice", Password: "wonderland", Role: "operator"}, token)
	mustStatus(t, resp, http.StatusCreated)

	// The newly created user can log in (verifies bcrypt round-trip via the store).
	login := f.post(t, "/v1/auth/login", models.LoginRequest{Username: "alice", Password: "wonderland"})
	mustStatus(t, login, http.StatusOK)
	var lr models.LoginResponse
	decodeBody(t, login, &lr)
	if lr.Role != "operator" || lr.Token == "" {
		t.Fatalf("unexpected login response: %+v", lr)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	f := newUserFixture(t, false)
	resp := f.post(t, "/v1/users", models.CreateUserRequest{Name: "admin", Password: "x", Role: "viewer"})
	mustStatus(t, resp, http.StatusConflict)
}

func TestCreateUser_InvalidRole(t *testing.T) {
	f := newUserFixture(t, false)
	resp := f.post(t, "/v1/users", models.CreateUserRequest{Name: "bob", Password: "x", Role: "wizard"})
	mustStatus(t, resp, http.StatusBadRequest)
}

func TestGetUser_NotFound(t *testing.T) {
	f := newUserFixture(t, false)
	mustStatus(t, f.get(t, "/v1/users/ghost"), http.StatusNotFound)
}

func TestUpdateUser_Role(t *testing.T) {
	f := newUserFixture(t, false)
	resp := f.do(t, http.MethodPatch, "/v1/users/viewer", models.UpdateUserRequest{Role: "operator"})
	mustStatus(t, resp, http.StatusOK)
	var u map[string]any
	decodeBody(t, resp, &u)
	if u["role"] != "operator" {
		t.Fatalf("expected role operator, got %v", u["role"])
	}
}

func TestUpdateUser_Password_AllowsLogin(t *testing.T) {
	f := newUserFixture(t, true)
	token := f.loginToken(t, "admin", "admin")
	resp := f.doAuth(t, http.MethodPatch, "/v1/users/ops", models.UpdateUserRequest{Password: "rotated"}, token)
	mustStatus(t, resp, http.StatusOK)
	login := f.post(t, "/v1/auth/login", models.LoginRequest{Username: "ops", Password: "rotated"})
	mustStatus(t, login, http.StatusOK)
}

func TestUpdateUser_Empty(t *testing.T) {
	f := newUserFixture(t, false)
	resp := f.do(t, http.MethodPatch, "/v1/users/ops", models.UpdateUserRequest{})
	mustStatus(t, resp, http.StatusBadRequest)
}

func TestDeleteUser(t *testing.T) {
	f := newUserFixture(t, false)
	mustStatus(t, f.delete(t, "/v1/users/viewer"), http.StatusNoContent)
	mustStatus(t, f.get(t, "/v1/users/viewer"), http.StatusNotFound)
}

func TestDeleteUser_LastAdmin(t *testing.T) {
	f := newUserFixture(t, false)
	// Remove the only admin → blocked.
	mustStatus(t, f.delete(t, "/v1/users/admin"), http.StatusConflict)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	f := newUserFixture(t, true)
	mustStatus(t, f.post(t, "/v1/auth/login", models.LoginRequest{Username: "admin", Password: "nope"}), http.StatusUnauthorized)
}

// With auth enabled the user routes are admin-only: no token → 401, non-admin → 403.
func TestUserRoutes_RequireAdmin(t *testing.T) {
	f := newUserFixture(t, true)
	mustStatus(t, f.get(t, "/v1/users"), http.StatusUnauthorized)

	viewerToken := f.loginToken(t, "viewer", "viewer")
	mustStatus(t, f.doAuth(t, http.MethodGet, "/v1/users", nil, viewerToken), http.StatusForbidden)

	adminToken := f.loginToken(t, "admin", "admin")
	mustStatus(t, f.doAuth(t, http.MethodGet, "/v1/users", nil, adminToken), http.StatusOK)
}
