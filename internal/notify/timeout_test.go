package notify

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A delivery that never returns would never be counted as failed.
func TestWebhooks_GiveUpOnAnUnresponsiveEndpoint(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	if httpClient.Timeout <= 0 {
		t.Fatal("webhook client has no timeout")
	}
	old := httpClient.Timeout
	httpClient.Timeout = 100 * time.Millisecond
	defer func() { httpClient.Timeout = old }()

	for _, n := range []Notifier{&WebhookNotifier{URL: srv.URL}, &SlackNotifier{WebhookURL: srv.URL}} {
		if err := n.Notify("rule", "message", "critical"); err == nil {
			t.Errorf("%T reported success without a response", n)
		}
	}
}
