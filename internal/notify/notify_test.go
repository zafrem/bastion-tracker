package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── Noop ─────────────────────────────────────────────────────────────────────

func TestNoop_ReturnsNil(t *testing.T) {
	n := Noop{}
	if err := n.Notify("rule", "message", "info"); err != nil {
		t.Fatalf("Noop.Notify should return nil, got: %v", err)
	}
}

func TestNoop_AllSeverities(t *testing.T) {
	n := Noop{}
	for _, sev := range []string{"info", "warning", "error", "critical"} {
		if err := n.Notify("r", "m", sev); err != nil {
			t.Errorf("severity %q: unexpected error: %v", sev, err)
		}
	}
}

// ─── SlackNotifier ────────────────────────────────────────────────────────────

func TestSlackNotifier_PostsToWebhook(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sn := &SlackNotifier{WebhookURL: srv.URL}
	if err := sn.Notify("test-rule", "something happened", "warning"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received == "" {
		t.Fatal("no request body received by mock server")
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(received), &payload); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if payload["text"] == "" {
		t.Error("expected non-empty 'text' field in Slack payload")
	}
}

func TestSlackNotifier_IncludesRuleName(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sn := &SlackNotifier{WebhookURL: srv.URL}
	sn.Notify("my-alert-rule", "msg", "info")

	if !strings.Contains(received, "my-alert-rule") {
		t.Errorf("payload should contain rule name, got: %s", received)
	}
}

func TestSlackNotifier_CriticalUsesRotatingLight(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sn := &SlackNotifier{WebhookURL: srv.URL}
	sn.Notify("rule", "msg", "critical")

	if !strings.Contains(received, ":rotating_light:") {
		t.Errorf("critical severity should use :rotating_light:, got: %s", received)
	}
}

func TestSlackNotifier_NonCriticalUsesWarning(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sn := &SlackNotifier{WebhookURL: srv.URL}
	sn.Notify("rule", "msg", "warning")

	if !strings.Contains(received, ":warning:") {
		t.Errorf("non-critical severity should use :warning:, got: %s", received)
	}
}

func TestSlackNotifier_SeverityUppercaseInText(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	sn := &SlackNotifier{WebhookURL: srv.URL}
	sn.Notify("rule", "msg", "error")

	if !strings.Contains(received, "ERROR") {
		t.Errorf("severity should be uppercase in message, got: %s", received)
	}
}

func TestSlackNotifier_BadURL_ReturnsError(t *testing.T) {
	sn := &SlackNotifier{WebhookURL: "http://127.0.0.1:0/nonexistent"}
	if err := sn.Notify("rule", "msg", "info"); err == nil {
		t.Fatal("expected error for unreachable URL")
	}
}

// ─── WebhookNotifier ──────────────────────────────────────────────────────────

func TestWebhookNotifier_PostsJSON(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wn := &WebhookNotifier{URL: srv.URL}
	if err := wn.Notify("wh-rule", "webhook message", "error"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(receivedContentType, "application/json") {
		t.Errorf("expected JSON content-type, got %q", receivedContentType)
	}

	var payload map[string]string
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("body not valid JSON: %v", err)
	}
	if payload["rule"] != "wh-rule" {
		t.Errorf("expected rule=wh-rule, got %q", payload["rule"])
	}
	if payload["message"] != "webhook message" {
		t.Errorf("expected message='webhook message', got %q", payload["message"])
	}
	if payload["severity"] != "error" {
		t.Errorf("expected severity=error, got %q", payload["severity"])
	}
}

func TestWebhookNotifier_PayloadHasTimestamp(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wn := &WebhookNotifier{URL: srv.URL}
	wn.Notify("rule", "msg", "info")

	var payload map[string]string
	json.Unmarshal(receivedBody, &payload)
	if payload["time"] == "" {
		t.Error("webhook payload should include 'time' field")
	}
}

func TestWebhookNotifier_BadURL_ReturnsError(t *testing.T) {
	wn := &WebhookNotifier{URL: "http://127.0.0.1:0/nonexistent"}
	if err := wn.Notify("rule", "msg", "info"); err == nil {
		t.Fatal("expected error for unreachable URL")
	}
}

// ─── Multi ────────────────────────────────────────────────────────────────────

type captureNotifier struct {
	calls []string
}

func (c *captureNotifier) Notify(ruleName, _, _ string) error {
	c.calls = append(c.calls, ruleName)
	return nil
}

type errorNotifier struct{ msg string }

func (e *errorNotifier) Notify(_, _, _ string) error {
	return &notifyErr{e.msg}
}

type notifyErr struct{ s string }

func (e *notifyErr) Error() string { return e.s }

func TestMulti_FansOutToAll(t *testing.T) {
	n1 := &captureNotifier{}
	n2 := &captureNotifier{}
	m := NewMulti(n1, n2)
	if err := m.Notify("rule", "msg", "info"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(n1.calls) != 1 || len(n2.calls) != 1 {
		t.Errorf("expected both notifiers called once; n1=%d n2=%d", len(n1.calls), len(n2.calls))
	}
}

func TestMulti_OneFailsReturnsError(t *testing.T) {
	n1 := &captureNotifier{}
	n2 := &errorNotifier{msg: "send failed"}
	m := NewMulti(n1, n2)
	err := m.Notify("rule", "msg", "info")
	if err == nil {
		t.Fatal("expected error when one notifier fails")
	}
	if !strings.Contains(err.Error(), "send failed") {
		t.Errorf("error should contain underlying message, got: %v", err)
	}
}

func TestMulti_AllFailReturnsAllErrors(t *testing.T) {
	n1 := &errorNotifier{msg: "err-1"}
	n2 := &errorNotifier{msg: "err-2"}
	m := NewMulti(n1, n2)
	err := m.Notify("rule", "msg", "info")
	if err == nil {
		t.Fatal("expected error when all notifiers fail")
	}
	if !strings.Contains(err.Error(), "err-1") || !strings.Contains(err.Error(), "err-2") {
		t.Errorf("expected both errors aggregated, got: %v", err)
	}
}

func TestMulti_AllSucceedReturnsNil(t *testing.T) {
	n1 := &captureNotifier{}
	n2 := &captureNotifier{}
	m := NewMulti(n1, n2)
	if err := m.Notify("rule", "msg", "warning"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestMulti_EmptyNotifiers(t *testing.T) {
	m := NewMulti()
	if err := m.Notify("rule", "msg", "info"); err != nil {
		t.Fatalf("empty multi should return nil, got %v", err)
	}
}

func TestMulti_PassesAllArgs(t *testing.T) {
	var capturedRule, capturedSev string
	called := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		capturedRule = payload["rule"]
		capturedSev = payload["severity"]
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wn := &WebhookNotifier{URL: srv.URL}
	m := NewMulti(wn)
	m.Notify("my-rule", "my-message", "critical")

	if !called {
		t.Fatal("notifier was not called")
	}
	if capturedRule != "my-rule" {
		t.Errorf("expected rule=my-rule, got %q", capturedRule)
	}
	if capturedSev != "critical" {
		t.Errorf("expected sev=critical, got %q", capturedSev)
	}
}
