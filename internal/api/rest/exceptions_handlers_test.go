package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/zafrem/bastion-tracker/internal/alerts"
	"github.com/zafrem/bastion-tracker/internal/audit"
	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/demo"
	"github.com/zafrem/bastion-tracker/internal/exceptions"
	"github.com/zafrem/bastion-tracker/internal/honeytoken"
	"github.com/zafrem/bastion-tracker/internal/hub"
	"github.com/zafrem/bastion-tracker/internal/incidents"
	"github.com/zafrem/bastion-tracker/internal/models"
	"github.com/zafrem/bastion-tracker/internal/monitor"
	"github.com/zafrem/bastion-tracker/internal/processor"
	"github.com/zafrem/bastion-tracker/internal/store"
	"github.com/zafrem/bastion-tracker/internal/validator"
)

func newExceptionServer(t *testing.T, withKey bool) (http.Handler, *store.Store, string, string) {
	t.Helper()
	s := store.New(1000)
	h := hub.New(64)
	al := alerts.New(nil, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	proc := processor.New(s, h, al, inc, ht)
	proc.SetValidator(validator.New())
	mon := monitor.New(monitor.Config{Mode: monitor.ModeOff})
	authCfg := &config.AuthConfig{Enabled: true, JWTSecret: "test-secret", JWTExpiry: "1h",
		Users: []config.UserConfig{
			{Name: "admin", Password: "admin", Role: "admin"},
			{Name: "ops", Password: "ops", Role: "operator"},
		}}
	key := ""
	var pub string
	if withKey {
		key, pub, _ = exceptions.GenerateKeyPair()
	}
	mgr, err := exceptions.NewManager(key, filepath.Join(t.TempDir(), "exc.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(s, h, proc, demo.NewEngine(proc), al, inc, ht, authCfg, audit.New(""), mon, nil, 0,
		WithExceptions(mgr))
	return srv.httpServer.Handler, s, pub, ""
}

func call(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func tokenFor(t *testing.T, h http.Handler, user, pass string) string {
	t.Helper()
	w := call(t, h, "POST", "/v1/auth/login", "", models.LoginRequest{Username: user, Password: pass})
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Token == "" {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	return out.Token
}

func TestExceptionEndpoints(t *testing.T) {
	h, st, pub, _ := newExceptionServer(t, true)
	admin := tokenFor(t, h, "admin", "admin")
	ops := tokenFor(t, h, "ops", "ops")
	body := map[string]any{
		"rule": "sentinel.out.pii:email", "modules": []string{"sentinel"}, "tenant_id": "acme",
		"justification": "support needs to see emails", "expires_at": time.Now().Add(48 * time.Hour),
	}

	if w := call(t, h, "POST", "/v1/exceptions", ops, body); w.Code != http.StatusForbidden {
		t.Fatalf("operator must not create exceptions, got %d", w.Code)
	}
	w := call(t, h, "POST", "/v1/exceptions", admin, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created exceptions.Exception
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.CreatedBy != "admin" {
		t.Errorf("CreatedBy=%q, want the authenticated user", created.CreatedBy)
	}

	bad := map[string]any{"rule": "sentinel.*", "modules": []string{"sentinel"}, "tenant_id": "acme",
		"justification": "long enough reason", "expires_at": time.Now().Add(time.Hour)}
	if w := call(t, h, "POST", "/v1/exceptions", admin, bad); w.Code != http.StatusBadRequest {
		t.Errorf("wildcard rule: got %d, want 400", w.Code)
	}

	w = call(t, h, "GET", "/v1/exceptions", admin, nil)
	var list struct {
		PublicKey  string                 `json:"public_key"`
		Exceptions []exceptions.Exception `json:"exceptions"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if list.PublicKey != pub || len(list.Exceptions) != 1 {
		t.Errorf("list: key match=%v n=%d", list.PublicKey == pub, len(list.Exceptions))
	}

	if w := call(t, h, "POST", "/v1/exceptions/"+created.ID+"/revoke", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, h, "POST", "/v1/exceptions/nope/revoke", admin, nil); w.Code != http.StatusNotFound {
		t.Errorf("revoke unknown: got %d, want 404", w.Code)
	}

	// Create and revoke are both recorded in the audit event log.
	n := 0
	for _, ev := range st.RecentEvents(models.QueryRequest{}, 100) {
		if ev.EventType == "exception_created" || ev.EventType == "exception_revoked" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("expected 2 audit events, got %d", n)
	}

	if w := call(t, h, "GET", "/v1/exceptions/export", admin, nil); w.Code != http.StatusOK {
		t.Errorf("export: %d", w.Code)
	}
}

func TestExceptionEndpointsDisabledWithoutKey(t *testing.T) {
	h, _, _, _ := newExceptionServer(t, false)
	admin := tokenFor(t, h, "admin", "admin")
	if w := call(t, h, "GET", "/v1/exceptions", admin, nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503 when no signing key is configured", w.Code)
	}
}
